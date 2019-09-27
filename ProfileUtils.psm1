using namespace System.Management.Automation
using namespace System.IO
using namespace System.Collections.Generic
using namespace Security.Principal

function Test-Command {
    [OutputType([Boolean])]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [String]$Command
    )
    return $null -ne (Get-Command $Command -ErrorAction SilentlyContinue)
}
function Set-EnvironmentVariable {
    <#
    .SYNOPSIS
    Creates or sets an environment variable.

    .DESCRIPTION
    Uses the .NET [Environment class](http://msdn.microsoft.com/en-us/library/z8te35sa) to create or set an environment variable in the Process, User, or Machine scopes.

    Changes to environment variables in the User and Machine scope are not picked up by running processes.  Any running processes that use this environment variable should be restarted.

    .LINK
    http://msdn.microsoft.com/en-us/library/z8te35sa

    .EXAMPLE
    Set-EnvironmentVariable -Name 'MyEnvironmentVariable' -Value 'Value1' -ForProcess

    Creates the `MyEnvironmentVariable` with an initial value of `Value1` in the process scope, i.e. the variable is only accessible in the current process.

    .EXAMPLE
    Set-EnvironmentVariable -Name 'MyEnvironmentVariable' -Value 'Value1' -ForComputer

    Creates the `MyEnvironmentVariable` with an initial value of `Value1` in the machine scope, i.e. the variable is accessible in all newly launched processes.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param(
        # The name of environment variable to add/set.
        [Parameter(Mandatory = $true)]
        [string]$Name,
        # The environment variable's value.
        [Parameter(Mandatory = $true)]
        [string]$Value,
        # Sets the environment variable for the current computer.
        [switch]$ForComputer,
        # Sets the environment variable for the current user.
        [switch]$ForUser,
        # Sets the environment variable for the current process.
        [switch]$ForProcess,
        # Set the variable in the current PowerShell session's `env:` drive, too. Normally, you have to restart your session to see the variable in the `env:` drive.
        [switch]$Force
    )
    if ( -not $ForProcess -and -not $ForUser -and -not $ForComputer ) {
        Write-Error -Message "Environment variable target not specified. You must supply one of the ForComputer, ForUser, or ForProcess switches."
        return
    }
    Invoke-Command -ScriptBlock {
        if ( $ForComputer ) { [EnvironmentVariableTarget]::Machine }
        if ( $ForUser ) { [EnvironmentVariableTarget]::User }
        if ( $ForProcess ) { [EnvironmentVariableTarget]::Process }
    } |
        Where-Object { $PSCmdlet.ShouldProcess( "$_-level environment variable '$Name'", "set") } |
        ForEach-Object { [Environment]::SetEnvironmentVariable( $Name, $Value, $_ ) }
}

function Remove-EnvironmentVariable {
    <#
    .SYNOPSIS
    Removes an environment variable.

    .DESCRIPTION
    Uses the .NET [Environment class](http://msdn.microsoft.com/en-us/library/z8te35sa) to remove an environment variable from the Process, User, or Computer scopes.

    Changes to environment variables in the User and Machine scope are not picked up by running processes.  Any running processes that use this environment variable should be restarted.

    Normally, you have to restart your PowerShell session/process to no longer see the variable in the `env:` drive. Use the `-Force` switch to also remove the variable from the `env:` drive. This functionality was added in Carbon 2.3.0.

    .LINK
    http://msdn.microsoft.com/en-us/library/z8te35sa

    .EXAMPLE
    Remove-EnvironmentVariable -Name 'MyEnvironmentVariable' -ForProcess

    Removes the `MyEnvironmentVariable` from the process scope.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param(
        # The environment variable to remove.
        [Parameter(Mandatory = $true)]
        [string]$Name,
        # Removes the environment variable for the current computer.
        [switch]$ForComputer,
        # Removes the environment variable for the current user.
        [switch]$ForUser,
        # Removes the environment variable for the current process.
        [switch]$ForProcess,
        # Remove the variable from the current PowerShell session's `env:` drive, too. Normally, you have to restart your session to no longer see the variable in the `env:` drive.
        [switch]$Force
    )
    if ( -not $ForProcess -and -not $ForUser -and -not $ForComputer ) {
        Write-Error -Message ('Environment variable target not specified. You must supply one of the ForComputer, ForUser, or ForProcess switches.')
        return
    }
    Invoke-Command -ScriptBlock {
        if ( $ForComputer ) { [EnvironmentVariableTarget]::Machine }
        if ( $ForUser ) { [EnvironmentVariableTarget]::User }
        if ( $ForProcess ) { [EnvironmentVariableTarget]::Process }
    } |
        Where-Object { $PSCmdlet.ShouldProcess( "$_-level environment variable '$Name'", "remove" ) } |
        ForEach-Object {
        $scope = $_
        [Environment]::SetEnvironmentVariable( $Name, $null, $scope )
        if ( $Force -and $scope -ne [EnvironmentVariableTarget]::Process ) {
            [Environment]::SetEnvironmentVariable($Name, $null, 'Process')
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
        [IO.DirectoryInfo]$Location,
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
        if ($n -gt $Commands.Count) {
            $n = $n - $Commands.Count
        }
        $Command = Get-History -Count $n | Select-Object -first 1
        if ($Command.CommandLine -imatch "^$($PSCmdlet.MyInvocation.InvocationName)(\s+)?(\d+)?(\s+)?(.*)?(-whatif)?") {
            Write-Debug "Clearing out command $Command"
            Clear-History -Count 1 -Id $Command.Id
            $Command = Get-History -Count $n | Select-Object -first 1
        }
        $id = $command.Id
        if ($PSCmdlet.ShouldProcess("Execute", "`"$($Command.CommandLine)`"")) {
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
    [OutputType([IO.DirectoryInfo])]
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
    "lexmultidomains3.lab.opentext.com" = @{
        ip            = "10.21.86.162"
        remoteSession = $null
    }
} | ForEach-Object { ([PSCustomObject]$_) }

Export-ModuleMember -Function *-* `
    -Variable ReleasesDirectory, NddResourcesDirectory, DriveMaps, Vms `
    -Alias *