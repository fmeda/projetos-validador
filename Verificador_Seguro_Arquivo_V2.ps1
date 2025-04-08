# Função para exibir mensagens informativas
function Display-Message {
    param (
        [string]$Message,
        [string]$Color = "Yellow"
    )
    Write-Host $Message -ForegroundColor $Color
}

# Função para verificar privilégios administrativos
function Check-AdminPrivileges {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Display-Message "Este programa requer privilégios de administrador. Por favor, reinicie-o como administrador." "Red"
        throw "Permissões insuficientes."
    }
    Display-Message "Permissões de administrador detectadas. Continuando o processo..." "Green"
}

# Função para validar uma URL
function Validate-URL {
    param (
        [string]$Url
    )
    Display-Message "Validando a URL..."
    if (-not ($Url.StartsWith("https://"))) {
        throw "Erro: Apenas URLs HTTPS são permitidas para downloads."
    }
    Display-Message "URL validada com sucesso." "Green"
}

# Função para calcular o hash de um arquivo remoto
function Calculate-RemoteFileHash {
    param (
        [string]$Url
    )
    Display-Message "Tentando identificar o hash remoto do arquivo..."
    try {
        $RemoteContent = Invoke-WebRequest -Uri $Url -Method Head
        if ($RemoteContent.Headers.'Content-MD5') {
            $RemoteHash = $RemoteContent.Headers.'Content-MD5'
            Display-Message "Hash remoto identificado: $RemoteHash" "Green"
            return $RemoteHash
        } else {
            Display-Message "O hash remoto não foi fornecido pelo servidor." "Yellow"
            return $null
        }
    } catch {
        Display-Message "Erro ao tentar identificar o hash remoto: $_" "Red"
        return $null
    }
}

# Função para verificar o hash local após o download
function Verify-LocalFileHash {
    param (
        [string]$FilePath,
        [string]$ExpectedHash
    )
    Display-Message "Verificando o hash do arquivo local..."
    $FileHash = (Get-FileHash -Path $FilePath -Algorithm "SHA256").Hash
    if ($FileHash -eq $ExpectedHash) {
        Display-Message "O hash local corresponde ao esperado. Verificação bem-sucedida!" "Green"
        return $FileHash
    } else {
        Display-Message "Os hashes não correspondem! O arquivo será excluído por segurança." "Red"
        Remove-Item $FilePath -Force
        throw "Falha na verificação do hash local."
    }
}

# Função para fazer o download do arquivo
function Download-File {
    param (
        [string]$Url,
        [string]$FilePath
    )
    Display-Message "Baixando o arquivo..."
    Invoke-WebRequest -Uri $Url -OutFile $FilePath
    Display-Message "Download concluído." "Green"
}

# Função para escanear o arquivo com o Windows Defender
function Scan-FileWithDefender {
    param (
        [string]$FilePath
    )
    Display-Message "Iniciando escaneamento de segurança..."
    Start-Process "C:\Program Files\Windows Defender\MpCmdRun.exe" `
        -ArgumentList "-Scan", "-ScanType", "3", "-File", $FilePath `
        -NoNewWindow -Wait
    Display-Message "Escaneamento de segurança concluído." "Green"
}

# Script principal
$LogFile = "C:\Temp\Processo_Log.txt"

try {
    # Etapa 0: Verificar privilégios administrativos
    Display-Message "Verificando privilégios administrativos..."
    Check-AdminPrivileges
    "[$(Get-Date)] Privilégios administrativos verificados." | Out-File -Append $LogFile

    # Solicitação da URL ao usuário
    $DownloadUrl = Read-Host "Digite a URL do arquivo para download (deve ser HTTPS)"
    Validate-URL -Url $DownloadUrl
    "[$(Get-Date)] URL validada: $DownloadUrl" | Out-File -Append $LogFile

    # Etapa 1: Calcular o hash remoto
    $RemoteHash = Calculate-RemoteFileHash -Url $DownloadUrl
    if (-not $RemoteHash) {
        Display-Message "ATENÇÃO: O provedor do arquivo não forneceu um hash para validação de integridade." "Yellow"
        Display-Message "Continuar o processo sem verificar a integridade pode ser arriscado." "Red"
        $UserChoice = Read-Host "Deseja continuar mesmo assim? (Digite 'sim' para prosseguir ou 'não' para cancelar)"
        if ($UserChoice -ne "sim") {
            throw "Processo encerrado pelo usuário devido à ausência do hash remoto."
        }
        "[$(Get-Date)] Usuário optou por continuar sem hash remoto." | Out-File -Append $LogFile
    }

    # Definir local para salvar o arquivo
    $FilePath = "C:\Temp\" + (Split-Path $DownloadUrl -Leaf)

    # Etapa 2: Download do arquivo
    Download-File -Url $DownloadUrl -FilePath $FilePath
    "[$(Get-Date)] Arquivo baixado: $FilePath" | Out-File -Append $LogFile

    # Etapa 3: Verificação do hash local (se o hash remoto foi fornecido)
    $FinalHash = ""
    if ($RemoteHash) {
        $FinalHash = Verify-LocalFileHash -FilePath $FilePath -ExpectedHash $RemoteHash
        "[$(Get-Date)] Hash local verificado com sucesso: $FinalHash" | Out-File -Append $LogFile
    }

    # Etapa 4: Escaneamento do arquivo
    Scan-FileWithDefender -FilePath $FilePath
    "[$(Get-Date)] Escaneamento concluído com sucesso." | Out-File -Append $LogFile

    # Informar o nome do arquivo e hash final ao usuário
    Display-Message "O nome do arquivo é: $(Split-Path $FilePath -Leaf)" "Cyan"
    if ($RemoteHash) {
        Display-Message "O hash do arquivo é: $FinalHash" "Cyan"
    } else {
        Display-Message "O hash não foi verificado porque não foi fornecido pelo servidor." "Yellow"
    }

    Display-Message "Processo concluído com sucesso!" "Green"
    "[$(Get-Date)] Processo concluído com sucesso." | Out-File -Append $LogFile

} catch {
    Display-Message "Erro durante o processo: $_" "Red"
    "[$(Get-Date)] Erro: $_" | Out-File -Append $LogFile
}
