$Env:CONDA_EXE = "/Users/hongjingtoh/Downloads/WirelessSmartLock/smart-lock-ctf-2025/venv/bin/conda"
$Env:_CE_M = $null
$Env:_CE_CONDA = $null
$Env:_CONDA_ROOT = "/Users/hongjingtoh/Downloads/WirelessSmartLock/smart-lock-ctf-2025/venv"
$Env:_CONDA_EXE = "/Users/hongjingtoh/Downloads/WirelessSmartLock/smart-lock-ctf-2025/venv/bin/conda"
$CondaModuleArgs = @{ChangePs1 = $True}
Import-Module "$Env:_CONDA_ROOT\shell\condabin\Conda.psm1" -ArgumentList $CondaModuleArgs

Remove-Variable CondaModuleArgs