#!/bin/bash
# quickstart.sh - Démarrage rapide de CLOBES PRO

echo "🚀 CLOBES PRO Quick Start"
echo "══════════════════════════════════════════════════"

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Vérifier l'installation
check_install() {
    if command -v clobes >/dev/null 2>&1; then
        echo -e "${GREEN}✓ CLOBES PRO est installé${NC}"
        clobes version
        return 0
    else
        echo -e "${RED}✗ CLOBES PRO n'est pas installé${NC}"
        return 1
    fi
}

# Installation rapide
install_quick() {
    echo -e "\n${CYAN}📦 Installation rapide...${NC}"
    
    # Télécharger
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL https://raw.githubusercontent.com/gopu-inc/clobes/main/install.sh -o /tmp/install-clobes.sh
    elif command -v wget >/dev/null 2>&1; then
        wget -q https://raw.githubusercontent.com/gopu-inc/clobes/main/install.sh -O /tmp/install-clobes.sh
    else
        echo -e "${RED}✗ curl ou wget requis${NC}"
        return 1
    fi
    
    # Installer
    chmod +x /tmp/install-clobes.sh
    echo -e "${YELLOW}⚠️  L'installation nécessite sudo${NC}"
    sudo /tmp/install-clobes.sh
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Installation réussie${NC}"
        return 0
    else
        echo -e "${RED}✗ Échec de l'installation${NC}"
        return 1
    fi
}

# Démonstration
show_demo() {
    echo -e "\n${CYAN}🎬 Démonstration rapide:${NC}"
    echo ""
    
    # 1. Version
    echo -e "${BLUE}1. Version:${NC}"
    clobes version
    
    # 2. HTTP GET
    echo -e "\n${BLUE}2. HTTP GET (remplace curl):${NC}"
    echo "clobes network get https://httpbin.org/get | head -5"
    clobes network get https://httpbin.org/get 2>/dev/null | head -5 || echo "  (test skipped)"
    
    # 3. System info
    echo -e "\n${BLUE}3. Informations système:${NC}"
    clobes system info | head -10
    
    # 4. File operations
    echo -e "\n${BLUE}4. Opérations fichiers:${NC}"
    echo "clobes file hash $(which clobes) sha256"
    clobes file hash $(which clobes) sha256 2>/dev/null || echo "  (test skipped)"
    
    # 5. Crypto
    echo -e "\n${BLUE}5. Cryptographie:${NC}"
    echo "clobes crypto generate-password"
    clobes crypto generate-password 2>/dev/null || echo "  (test skipped)"
}

# Exemples d'utilisation
show_examples() {
    echo -e "\n${CYAN}📚 Exemples d'utilisation:${NC}"
    echo ""
    
    echo -e "${GREEN}🌐 Réseau (remplace curl/wget):${NC}"
    echo "  clobes network get https://api.github.com/users/octocat"
    echo "  clobes network download https://example.com/file.zip"
    echo "  clobes network ping google.com -c 5"
    echo "  clobes network scan example.com 80-443"
    echo "  clobes network speedtest"
    echo ""
    
    echo -e "${GREEN}💻 Système:${NC}"
    echo "  clobes system info"
    echo "  clobes system processes"
    echo "  clobes system memory"
    echo "  clobes system disks"
    echo "  clobes system logs"
    echo ""
    
    echo -e "${GREEN}📁 Fichiers:${NC}"
    echo "  clobes file find /var/log *.log"
    echo "  clobes file size /etc/passwd"
    echo "  clobes file hash document.txt"
    echo "  clobes file compare file1.txt file2.txt"
    echo ""
    
    echo -e "${GREEN}🔐 Cryptographie:${NC}"
    echo "  clobes crypto hash "secret password""
    echo "  clobes crypto generate-password 20"
    echo "  clobes crypto encode base64 "hello world""
    echo "  clobes crypto encode url "param=value&test=ok""
    echo ""
    
    echo -e "${GREEN}👨‍💻 Développement:${NC}"
    echo "  clobes dev compile program.c"
    echo "  clobes dev run program"
    echo "  clobes dev format source.py"
    echo "  clobes dev analyze module.c"
    echo ""
    
    echo -e "${YELLOW}💡 Astuce: Utilisez la complétion par tabulation!${NC}"
    echo "  clobes net<TAB>   # Complète network"
    echo "  clobes sys<TAB>   # Complète system"
    echo "  clobes <TAB><TAB> # Liste toutes les commandes"
}

# Configuration rapide
quick_config() {
    echo -e "\n${CYAN}⚙️  Configuration rapide:${NC}"
    
    # Créer config utilisateur
    mkdir -p ~/.config/clobes
    cat > ~/.config/clobes/user.json << 'EOF'
{
    "colors": true,
    "progress_bars": true,
    "timeout": 30,
    "cache": true,
    "aliases": {
        "cg": "network get",
        "cdl": "network download",
        "cinfo": "system info"
    }
}
EOF
    
    # Alias bash
    if ! grep -q "CLOBES PRO" ~/.bashrc 2>/dev/null; then
        echo "" >> ~/.bashrc
        echo "# CLOBES PRO Aliases" >> ~/.bashrc
        echo "alias cget='clobes network get'" >> ~/.bashrc
        echo "alias cpost='clobes network post'" >> ~/.bashrc
        echo "alias cdownload='clobes network download'" >> ~/.bashrc
        echo "alias cinfo='clobes system info'" >> ~/.bashrc
        echo "alias cping='clobes network ping'" >> ~/.bashrc
        echo "" >> ~/.bashrc
        echo -e "${GREEN}✓ Aliases ajoutés à ~/.bashrc${NC}"
    fi
    
    echo -e "${GREEN}✓ Configuration utilisateur créée${NC}"
}

# Menu principal
main() {
    echo "══════════════════════════════════════════════════"
    echo "1. Vérifier l'installation"
    echo "2. Installer rapidement"
    echo "3. Voir la démonstration"
    echo "4. Afficher les exemples"
    echo "5. Configuration rapide"
    echo "6. Quitter"
    echo "══════════════════════════════════════════════════"
    
    read -p "Choix [1-6]: " choice
    
    case $choice in
        1) check_install ;;
        2) install_quick ;;
        3) show_demo ;;
        4) show_examples ;;
        5) quick_config ;;
        6) echo "Au revoir!"; exit 0 ;;
        *) echo -e "${RED}Choix invalide${NC}" ;;
    esac
    
    echo ""
    read -p "Appuyez sur Entrée pour continuer..." dummy
    clear
    main
}

# Démarrer
clear
main
