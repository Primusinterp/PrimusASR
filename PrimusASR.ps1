function Get-ExclusionsFromEvent {
    param (
        [string]$EventXml,
        [string]$ExclusionType
    )

    $exclusions = @()

    if ($ExclusionType -eq 'Defender') {
        $pattern = 'HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\[^<]+'
        $matches = [regex]::Matches($EventXml, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        foreach ($match in $matches) {
            $exclusions += $match.Value
        }
    }
    elseif ($ExclusionType -eq 'ASR') {

        
        $pattern = 'HKLM[\\]+SOFTWARE[\\]+Microsoft[\\]+Windows Defender[\\]+Windows Defender Exploit Guard[\\]+ASR[\\]+ASROnlyExclusions[^<]+'
        $matches = [regex]::Matches($EventXml, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        foreach ($match in $matches) {
            $exclusions += $match.Value
        }
        
        $pattern = 'HKLM[\\]+SOFTWARE[\\]+Policies[\\]+Microsoft[\\]+Windows Defender[\\]+Policy Manager[\\]+Windows Defender Exploit Guard[\\]+ASR[\\]+ASROnlyExclusions[^<]+'
        $matches = [regex]::Matches($EventXml, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        foreach ($match in $matches) {
            $exclusions += $match.Value
        }
        
        $pattern = 'HKLM[\\]+SOFTWARE[\\]+Policies[\\]+Microsoft[\\]+Windows Defender[\\]+Policy Manager[\\]+Windows Defender Exploit Guard[\\]+ASR[\\]+ASROnlyPerRuleExclusions[^<]+'
        $matches = [regex]::Matches($EventXml, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        foreach ($match in $matches) {
            $exclusions += $match.Value
        }
    }

    return $exclusions
}

function Get-ASRRulesFromEvent {
    param (
        [string]$EventXml,
        [System.Diagnostics.Eventing.Reader.EventLogRecord]$Event
    )

    $asrRules = @{}
    # Regex shenanigans
    $asrRulePathPattern = '(?:HKLM[\\]+SOFTWARE[\\]+Policies[\\]+Microsoft[\\]+Windows Defender[\\]+Policy Manager[\\]+Windows Defender Exploit Guard[\\]+ASR[\\]+Rules[\\]+|ASR[\\]+Rules[\\]+)([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\s*=\s*(0x[0-9a-fA-F]+)'
    
    $matches = [regex]::Matches($EventXml, $asrRulePathPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    
    foreach ($match in $matches) {
        $ruleId = $match.Groups[1].Value
        $hexAction = $match.Groups[2].Value
        
        try {
            $actionValue = [Convert]::ToInt32($hexAction, 16)
        }
        catch {
            continue
        }
        
        $ruleName = Get-ASRRuleName -RuleId $ruleId
        if ($ruleName) {
            $action = Get-ActionName -ActionValue $actionValue
            
            $normalizedRuleId = $ruleId.ToLower()
            $asrRules[$normalizedRuleId] = @{
                Name = $ruleName
                Action = $action
            }
        }
    }
    
    return $asrRules
}

function Get-ASRRuleName {
    param (
        [string]$RuleId
    )
    
    $normalizedRuleId = $RuleId.ToLower()
    # Rules IDs and their names
    $ruleMap = @{
        "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Block abuse of exploited vulnerable signed drivers"
        "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "Block Adobe Reader from creating child processes"
        "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "Block all Office applications from creating child processes"
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Block credential stealing from the Windows local security authority subsystem (lsass.exe)"
        "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = "Block executable content from email client and webmail"
        "01443614-cd74-433a-b99e-2ecdc07bfc25" = "Block executable files from running unless they meet a prevalence, age, or trusted list criteria"
        "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "Block execution of potentially obfuscated scripts"
        "d3e037e1-3eb8-44c8-a917-57927947596d" = "Block JavaScript or VBScript from launching downloaded executable content"
        "3b576869-a4ec-4529-8536-b80a7769e899" = "Block Office applications from creating executable content"
        "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = "Block Office applications from injecting code into other processes"
        "26190899-1602-49e8-8b27-eb1d0a1ce869" = "Block Office communication applications from creating child processes"
        "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Block persistence through WMI event subscription"
        "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "Block process creations originating from PSExec and WMI commands"
        "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Block untrusted and unsigned processes that run from USB"
        "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = "Block Win32 API calls from Office macro"
        "c1db55ab-c21a-4637-bb3f-a12568109d35" = "Use advanced protection against ransomware"
    }
    
    return $ruleMap[$normalizedRuleId]
}

function Get-ASRRuleAction {
    param (
        [string]$EventXml,
        [string]$RuleId
    )
    

    
    $actionPattern = "$([regex]::Escape($RuleId)).*?(\d+)"
    $match = [regex]::Match($EventXml, $actionPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    
    if ($match.Success) {
        $actionValue = [int]$match.Groups[1].Value
        return Get-ActionName -ActionValue $actionValue
    }
    
    if ($EventXml -match 'AttackSurfaceReductionRules_Actions') {
        $actionMatch = [regex]::Match($EventXml, 'AttackSurfaceReductionRules_Actions[^>]*>([^<]+)')
        if ($actionMatch.Success) {
            $actions = $actionMatch.Groups[1].Value -split ','
            if ($actions.Count -gt 0) {
                $actionValue = [int]($actions[0].Trim())
                return Get-ActionName -ActionValue $actionValue
            }
        }
    }
    
    return "Unknown"
}

function Get-ActionName {
    param (
        [int]$ActionValue
    )
    
    switch ($ActionValue) {
        0 { return "Disabled" }
        1 { return "Block" }
        2 { return "Audit" }
        6 { return "Warn" }
        default { return "Unknown ($ActionValue)" }
    }
}

Write-Host "`n=== Windows Defender Exclusions Scanner ===" -ForegroundColor Cyan
Write-Host "Scanning for Defender and ASR Exclusions...`n" -ForegroundColor Green

try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Windows Defender/Operational'
        ID = 5007
    } -ErrorAction Stop

    if ($events.Count -eq 0) {
        Write-Host "No exclusion events found." -ForegroundColor Yellow
        exit
    }

    Write-Host "Found $($events.Count) Event ID 5007 entries. Processing...`n" -ForegroundColor Gray

    $foundExclusions = $false
    $allASRRules = @{}
    $allDefenderExclusions = @()
    $allASRExclusions = @()
    $totalDisabled = 0
    $totalAudit = 0
    $totalBlock = 0
    $totalWarn = 0

    $sortedEvents = $events | Sort-Object -Property TimeCreated -Descending

    foreach ($event in $sortedEvents) {
        $eventXml = $event.ToXml()
        
        $defenderExclusions = Get-ExclusionsFromEvent -EventXml $eventXml -ExclusionType 'Defender'
        foreach ($exclusion in $defenderExclusions) {
            if ($exclusion -and $exclusion -notin $allDefenderExclusions) {
                $foundExclusions = $true
                $allDefenderExclusions += $exclusion
            }
        }
        
        $asrExclusions = Get-ExclusionsFromEvent -EventXml $eventXml -ExclusionType 'ASR'
        foreach ($exclusion in $asrExclusions) {
            if ($exclusion -and $exclusion -notin $allASRExclusions) {
                $foundExclusions = $true
                $allASRExclusions += $exclusion
            }
        }
        
        $asrRules = Get-ASRRulesFromEvent -EventXml $eventXml -Event $event
        foreach ($ruleId in $asrRules.Keys) {
            $normalizedRuleId = $ruleId.ToLower()
            if (-not $allASRRules.ContainsKey($normalizedRuleId)) {
                $allASRRules[$normalizedRuleId] = $asrRules[$ruleId]
                
                switch ($asrRules[$ruleId].Action) {
                    "Disabled" { $totalDisabled++ }
                    "Audit" { $totalAudit++ }
                    "Block" { $totalBlock++ }
                    "Warn" { $totalWarn++ }
                }
            }
        }
    }

    Write-Host ""
    Write-Host "===================================== Defender Exclusions ======================================" -ForegroundColor Cyan
    if ($allDefenderExclusions.Count -gt 0) {
        foreach ($exclusion in $allDefenderExclusions) {
            Write-Host "[+] $exclusion" -ForegroundColor Yellow
            Write-Host ""  
        }
    }
    else {
        Write-Host "No Defender exclusions found." -ForegroundColor Gray
    }
    Write-Host ""

    Write-Host "===================================== ASR Exclusions ======================================" -ForegroundColor Cyan
    if ($allASRExclusions.Count -gt 0) {
        foreach ($exclusion in $allASRExclusions) {
            Write-Host "[+] $exclusion" -ForegroundColor Yellow
            Write-Host ""  
        }
    }
    else {
        Write-Host "No ASR exclusions found." -ForegroundColor Gray
    }
    Write-Host ""

    Write-Host "===================================== ASR Summary ======================================" -ForegroundColor Cyan
    if ($allASRRules.Count -gt 0) {
        Write-Host "=> There's $($allASRRules.Count) rules configured" -ForegroundColor White
        Write-Host "=> $totalDisabled in Disabled Mode ** $totalAudit in Audit Mode ** $totalBlock in Block Mode ** $totalWarn in Warn Mode" -ForegroundColor White
        Write-Host ""
        Write-Host "===================================== ASR Rules ======================================" -ForegroundColor Cyan
        Write-Host ""
        
        foreach ($ruleId in ($allASRRules.Keys | Sort-Object)) {
            $rule = $allASRRules[$ruleId]
            Write-Host "Rule ID  : $ruleId" -ForegroundColor Cyan
            Write-Host "Name     : $($rule.Name)" -ForegroundColor White
            Write-Host "Action   : $($rule.Action)" -ForegroundColor Yellow
            Write-Host ""
        }
    }
    else {
        Write-Host "No ASR rules found in the event log." -ForegroundColor Gray
        Write-Host ""
        Write-Host "Note: Event ID 5007 only logs configuration changes. Rules that were never modified" -ForegroundColor Yellow
        Write-Host "      may not appear in the event log." -ForegroundColor Yellow
    }
    Write-Host ""

    Write-Host "=== Scan Complete ===" -ForegroundColor Cyan
}
catch {
    if ($_.Exception.Message -like "*No events were found*") {
        Write-Host "No exclusion events found in the log." -ForegroundColor Yellow
    }
    else {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
} 