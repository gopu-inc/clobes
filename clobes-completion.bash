# clobes-completion.bash - Bash completion for CLOBES PRO

_clobes_complete() {
    local cur prev words cword
    _init_completion || return
    
    local main_commands="version help network system file crypto dev db cloud docker k8s monitor backup media text math ai"
    local network_cmds="get post put delete head options download upload ping scan dns whois traceroute speedtest myip benchmark ssh ftp sftp websocket"
    local system_cmds="info processes users disks memory cpu network services logs update clean reboot shutdown"
    local file_cmds="find size hash compare backup restore compress decompress encrypt decrypt stats"
    local crypto_cmds="hash encrypt decrypt generate-password generate-key encode decode"
    local dev_cmds="compile run debug profile test format analyze docs lint"
    
    case ${#words[@]} in
        2)
            # Main command
            COMPREPLY=($(compgen -W "$main_commands" -- "$cur"))
            ;;
        3)
            # Subcommand
            case ${words[1]} in
                network)
                    COMPREPLY=($(compgen -W "$network_cmds" -- "$cur"))
                    ;;
                system)
                    COMPREPLY=($(compgen -W "$system_cmds" -- "$cur"))
                    ;;
                file)
                    COMPREPLY=($(compgen -W "$file_cmds" -- "$cur"))
                    ;;
                crypto)
                    COMPREPLY=($(compgen -W "$crypto_cmds" -- "$cur"))
                    ;;
                dev)
                    COMPREPLY=($(compgen -W "$dev_cmds" -- "$cur"))
                    ;;
                help)
                    COMPREPLY=($(compgen -W "$main_commands" -- "$cur"))
                    ;;
            esac
            ;;
        4)
            # Arguments for subcommands
            case ${words[1]} in
                network)
                    case ${words[2]} in
                        get|post|put|delete|head|options|upload)
                            # URLs
                            COMPREPLY=($(compgen -f -X '!*' -- "$cur"))
                            ;;
                        download)
                            # URL then filename
                            if [ $cword -eq 3 ]; then
                                COMPREPLY=($(compgen -f -X '!*' -- "$cur"))
                            fi
                            ;;
                        ping|scan|dns|whois|traceroute)
                            # Hostnames/IPs
                            COMPREPLY=()
                            ;;
                    esac
                    ;;
                file)
                    case ${words[2]} in
                        find)
                            if [ $cword -eq 3 ]; then
                                COMPREPLY=($(compgen -d -- "$cur"))
                            fi
                            ;;
                        size|hash|compress|decompress|stats)
                            COMPREPLY=($(compgen -f -- "$cur"))
                            ;;
                        compare)
                            if [ $cword -eq 3 ] || [ $cword -eq 4 ]; then
                                COMPREPLY=($(compgen -f -- "$cur"))
                            fi
                            ;;
                    esac
                    ;;
                crypto)
                    case ${words[2]} in
                        encode|decode)
                            COMPREPLY=($(compgen -W "base64 url" -- "$cur"))
                            ;;
                    esac
                    ;;
                dev)
                    case ${words[2]} in
                        compile|run|debug|profile|format|analyze|lint)
                            COMPREPLY=($(compgen -f -- "$cur"))
                            ;;
                    esac
                    ;;
            esac
            ;;
        *)
            # Default completion
            COMPREPLY=($(compgen -f -- "$cur"))
            ;;
    esac
}

complete -F _clobes_complete clobes
