using namespace System.Management.Automation
using namespace System.IO
using namespace System.Collections.Generic
using namespace Security.Principal

function Test-Command {
    [OutputType([Boolean])]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [String]$Command
    )
    return $null -ne (Get-Command $Command -ErrorAction SilentlyContinue)
}
if (!(Get-Command Set-EnvironmentVariable)) {
    <#
        .Synopsis
        Set an environment variable in the current session
        .Description
        Set an environment variable in the current session with the option to persist between sessions
        .Parameter Name
        Specifies the name of the variable to set. If it does not exist and the `-Force` parameter is not used, this will throw an error
    #>
    function Set-EnvironmentVariable {
        [CmdletBinding()]
        Param(
            [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
            [ValidateScript( { Test-Path ([Path]::GetFullPath($_)) })]
            [String]$Value,
            [Parameter()]
            [switch]$Force,
            [Parameter()]
            [switch]$Persist
        )
        DynamicParam {
            $ParamDictionary = [RuntimeDefinedParameterDictionary]::new()

            $Target = [RuntimeDefinedParameter]::new('Target', [string], @(
                    [ParameterAttribute]@{
                        HelpMessage                     = 'Whose path to modify'
                        Mandatory                       = $false
                        ValueFromPipelineByPropertyName = $false
                    }
                    [ValidateSetAttribute][string[]]([EnvironmentVariableTarget].GetEnumNames())
                ))
            $Target.Value = "User"
            $ParamDictionary.Add('Target', $Target)

            $ParamDictionary.Add('Name', [RuntimeDefinedParameter]::new('Name', [string], @(
                        [ParameterAttribute]@{
                            HelpMessage                     = 'Name of Environment Variable'
                            Mandatory                       = $True
                            ValueFromPipelineByPropertyName = $false
                        }
                        [ValidateSetAttribute][string[]](Get-ChildItem -Path Env:\ | Select-Object -ExpandProperty "Path")
                        [ValidateScriptAttribute]::new( {
                                if ((-not $Force) -and (-not (Test-Path "Env:\`"$_`""))) {
                                    throw "No environment variable named ($_) found. Use -Force to create it"
                                }
                                return $true
                            })
                    )))

            return $ParamDictionary
        }
        Begin {
            $Target = "$($Target.Value)"
            [EnvironmentVariableTarget]$ResolvedTarget = [EnvironmentVariableTarget]::$Target
        }
        Process {
            if ($Persist) {
                [Environment]::SetEnvironmentVariable($Name, $Value, $ResolvedTarget)
            }
            else {
                New-Item -Path "Env:\`"$($Name.Value)`"" -Value $Value -Force
            }
        }
    }
}

function Add-ToPath {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [ValidateScript( { Test-Path ([Path]::GetFullPath($_)) })]
        [String]$Path
    )
    DynamicParam {
        $ParamDictionary = [RuntimeDefinedParameterDictionary]::new()
        $ParamDictionary.Add('Target', [RuntimeDefinedParameter]::new('Target', [string], @(
                    [ParameterAttribute]@{
                        HelpMessage = 'Whose path to modify'
                    }
                    [ValidateSetAttribute][string[]]([EnvironmentVariableTarget].GetEnumNames())
                )))
        return $ParamDictionary
    }
    Begin {
        [String]$Target = $PSBoundParameters['Target']
        if (-not $Target) {
            $Target = "User"
        }
        [String]$Path = [Path]::GetFullPath($Path)
        [EnvironmentVariableTarget]$ResolvedTarget = [EnvironmentVariableTarget]::$Target
        [string]$CurrentPath = [Environment]::GetEnvironmentVariable("Path", $ResolvedTarget)
        if ($CurrentPath.ToLower().Split(';') -contains $Path.ToLower()) {
            throw "Path for $Target already contains $Path"
        }
    }
    Process {
        [Environment]::SetEnvironmentVariable("Path", $CurrentPath + ";$Path", $ResolvedTarget)
    }
}

function Remove-FromPath {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [ValidateScript( { Test-Path ([Path]::GetFullPath($_)) })]
        [String]$Path
    )
    DynamicParam {
        $ParamDictionary = [RuntimeDefinedParameterDictionary]::new()
        $ParamDictionary.Add('Target', [RuntimeDefinedParameter]::new('Target', [string], @(
                    [ParameterAttribute]@{
                        HelpMessage = 'Whose path to modify'
                    }
                    [ValidateSetAttribute][string[]]([EnvironmentVariableTarget].GetEnumNames())
                )))
        return $ParamDictionary
    }
    Begin {
        [String]$Target = $PSBoundParameters['Target']
        if (-not $Target) {
            $Target = "User"
        }
        [String]$Path = [Path]::GetFullPath($Path)
        [EnvironmentVariableTarget]$ResolvedTarget = [EnvironmentVariableTarget]::$Target
        [String[]]$CurrentPathParts = [Environment]::GetEnvironmentVariable("Path", $ResolvedTarget) -split ';'
        $CurrentPathParts
    }
    Process {
        if ($Path -inotin $CurrentPathParts) {
            # Thing is already not in the path so don't even process
            return
        }
        [String[]] $ModifiedPathParts = $CurrentPathParts | Where-Object { $_ -ine $CurrentPathParts }
        return $ModifiedPathParts -join ';'
        # [Environment]::SetEnvironmentVariable("Path", ($ModifiedPathParts -join ';'), $ResolvedTarget)
    }
}

function Invoke-AtLocation {
    [CmdletBinding(SupportsShouldProcess)]
    Param(
        [Parameter(ValueFromPipeline, Mandatory = $true)]
        [DirectoryInfo]$Location,
        [Parameter(Mandatory = $true)]
        [scriptblock]$ExecutionBlock
    )
    Process {
        try {
            Push-Location
            Set-Location $Location
            Write-Verbose ("Executing block: `n" + $executionBlock.Ast.Extent.Text)
            if ($PSCmdlet.ShouldProcess($executionBlock.Ast.Extent.Text, "Execute at $Location")) {
                Invoke-Command -ScriptBlock $ExecutionBlock
            }
        }
        finally {
            Pop-Location
        }
    }
}

function Invoke-LastCommand {
    [CmdletBinding(SupportsShouldProcess)]
    Param(
        <# The nth command from the bottom of the history to invoke #>
        [int]$n = 1
    )
    Process {
        $Commands = Get-History
        if($n -gt $Commands.Count) {
            $n = $n - $Commands.Count
        }
        $Command = Get-History -Count $n | Select-Object -first 1
        if($Command.CommandLine -imatch "^$($PSCmdlet.MyInvocation.InvocationName)(\s+)?(\d+)?(\s+)?(.*)?(-whatif)?") {
            Write-Debug "Clearing out command $Command"
            Clear-History -Count 1 -Id $Command.Id
            $Command = Get-History -Count $n | Select-Object -first 1
        }
        $id = $command.Id
        if($PSCmdlet.ShouldProcess("Execute", "`"$($Command.CommandLine)`"")) {
            Invoke-History -Id $id
        }
    }
}

Set-Alias -Name "<" -Value "Invoke-LastCommand" -Force
function Format-Json {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [string]$Input
    )
    Process {
        return $_ | python -m json.tool
    }
}

Set-Alias -Name "json" -Value "Format-Json"

function Test-Administrator {
    [CmdletBinding()]
    Param ()
    Process {
        return ([WindowsPrincipal][WindowsIdentity]::GetCurrent()).IsInRole([WindowsBuiltInRole] "Administrator")
    }
}
function Compare-ObjectProperties {
    Param(
        [PSObject]$ReferenceObject,
        [PSObject]$DifferenceObject,
        [Switch]$IncludeEqual
    )
    DynamicParam {
        $ParamDictionary = [RuntimeDefinedParameterDictionary]::new()
        $ValidProperties = (($ReferenceObject | Get-Member -MemberType Property, NoteProperty) + ($DifferenceObject | Get-Member -MemberType Property, NoteProperty)) | Select-Object -ExpandProperty Name | Sort-Object | Select-Object -Unique
    
        $Include = [RuntimeDefinedParameter]::new('Include', [string[]], @(
                [ParameterAttribute]@{
                    ParameterSetName = "IncludeProperties"
                }
                [ValidateSetAttribute][string[]]($ValidProperties)
            ))
        $ParamDictionary.Add($Include.Name, $Include)

        $Exclude = [RuntimeDefinedParameter]::new('Exclude', [string[]], @(
                [ParameterAttribute]@{
                    ParameterSetName = "ExcludeProperties"
                }
                [ValidateSetAttribute][string[]]($ValidProperties)
            ))
        $ParamDictionary.Add($Exclude.Name, $Exclude)
        
        return $ParamDictionary
    }
    Process {
        $objprops = $ReferenceObject | Get-Member -MemberType Property, NoteProperty | Select-Object -ExpandProperty Name
        $objprops += $DifferenceObject | Get-Member -MemberType Property, NoteProperty | Select-Object -ExpandProperty Name
        $objprops = $objprops | Sort-Object | Select-Object -Unique
        $diffs = @()
        foreach ($objprop in $objprops) {
            $diff = Compare-Object $ReferenceObject $DifferenceObject -Property $objprop
            if ($diff) {
                $diffprops = @{
                    PropertyName  = $objprop
                    RefValue      = ($diff | Where-Object {$_.SideIndicator -eq ''} | ForEach-Object $($objprop))
                    DiffIndicator = ""
                }
                $diffs += New-Object PSObject -Property $diffprops
            }
            elseif ($IncludeEqual) {
                $diffprops = @{
                    PropertyName  = $objprop
                    RefValue      = $ReferenceObject."$objprop"
                    DiffValue     = $DifferenceObject."$objprop"
                    DiffIndicator = "=="
                }
                $diffs += New-Object PSObject -Property $diffprops
            }
        }
        if ($diffs) {
            return $diffs | Select-Object PropertyName, RefValue, DiffValue, DiffIndicator
        }
    }
}

function Get-QAFolder {
    [CmdletBinding()]
    [OutputType([DirectoryInfo])]
    Param(
        [string]$Name = "Wes"
    )
    return Join-Path (Join-Path $DriveMaps['r-d'].UncPath  "QualityAssurance") $Name
}

[System.Collections.Generic.SortedDictionary[string, DriveMapPair]]$DriveMaps = @{}

$Drives = Get-PSDrive
$Drives |
Where-Object { 
    $_.Provider.Name -ieq "filesystem" `
    -and $_.Name.Length -eq 1 `
    -and $_.DisplayRoot -ne $null `
    -and -not $_.DisplayRoot.StartsWith($_.Name) 
} |
ForEach-Object { 
    $Pair = [DriveMapPair]::new($_.DisplayRoot, $_.Root)
    $DriveMaps[$Pair.Name] = $Pair
    New-PSDrive -Name $Pair.Name -PSProvider FileSystem -Root $Pair.UncPath | Out-Null
}
$ReleasesDirectory = $DriveMaps["Releases"].UncPath
$NddResourcesDirectory = $DriveMaps["testcase-repo"].PrependUncPath("\Active\Resources")

$Vms = @{
    "win2016wes1.lab.opentext.com" = @{
        ip = "10.21.86.25"
        remoteSession = $null
    }
    "win2016wes2.lab.opentext.com" = @{
        ip = "10.21.86.24"
        remoteSession = $null
    }
    "win2016wes3.lab.opentext.com" = @{
        ip = "10.21.86.45"
        remoteSession = $null
    }
    "lexmultidomains3.lab.opentext.com" = @{
        ip = "10.21.86.162"
        remoteSession = $null
    }
 } | ForEach-Object { ([PSCustomObject]$_) }

Export-ModuleMember -Function *-* `
    -Variable ReleasesDirectory, NddResourcesDirectory, DriveMaps, Vms `
    -Alias *