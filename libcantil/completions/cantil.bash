# Bash completion for the cantil CLI (Cantil hardware CA host client).
# Install (system-wide): copy to /etc/bash_completion.d/cantil
# Install (user):        source this file from ~/.bashrc or ~/.bash_profile
#                        or drop in ~/.local/share/bash-completion/completions/cantil

_cantil_ports() {
    local ports
    ports=$(ls /dev/ttyACM* /dev/ttyUSB* 2>/dev/null)
    COMPREPLY+=($(compgen -W "$ports" -- "$1"))
}

_cantil_trust_opts='--trust --ca-dir --ca-cert --cn --client-cert --client-chain'

_cantil() {
    local cur prev words cword
    _init_completion || return

    local commands='list pair status random provision-ca sign-key-slot protect
        unprotect key-chain sign-csr-slot session-cert session-csr ca-cert
        session-sign session-push clients unpair name roundtrip'

    # First word after cantil is always the subcommand
    local cmd=''
    local i
    for (( i=1; i < cword; i++ )); do
        if [[ "${words[i]}" != -* ]]; then
            cmd="${words[i]}"
            break
        fi
    done

    if [[ -z "$cmd" ]]; then
        COMPREPLY=($(compgen -W "$commands" -- "$cur"))
        return
    fi

    case "$cmd" in
        list)
            # No arguments
            ;;

        pair)
            case "$prev" in
                --passkey)
                    COMPREPLY=()
                    ;;
                --client-cert|--client-chain)
                    _filedir '*.der'
                    ;;
                *)
                    if [[ "$cur" == -* ]]; then
                        COMPREPLY=($(compgen -W '--force --passkey --client-cert --client-chain' -- "$cur"))
                    else
                        _cantil_ports "$cur"
                    fi
                    ;;
            esac
            ;;

        status|session-cert|session-csr|ca-cert|clients)
            case "$prev" in
                --trust)
                    COMPREPLY=($(compgen -W 'none pin ca ca+cn' -- "$cur"))
                    ;;
                --ca-dir)
                    _filedir -d
                    ;;
                --ca-cert|--client-cert|--client-chain)
                    _filedir '*.der'
                    ;;
                --cn)
                    COMPREPLY=()
                    ;;
                *)
                    if [[ "$cur" == -* ]]; then
                        COMPREPLY=($(compgen -W "$_cantil_trust_opts" -- "$cur"))
                    else
                        _cantil_ports "$cur"
                    fi
                    ;;
            esac
            ;;

        random|roundtrip)
            case "$prev" in
                --trust)
                    COMPREPLY=($(compgen -W 'none pin ca ca+cn' -- "$cur"))
                    ;;
                --ca-dir)
                    _filedir -d
                    ;;
                --ca-cert|--client-cert|--client-chain)
                    _filedir '*.der'
                    ;;
                --cn)
                    COMPREPLY=()
                    ;;
                "$cmd")
                    # expecting the numeric argument next
                    COMPREPLY=()
                    ;;
                *)
                    if [[ "$cur" == -* ]]; then
                        COMPREPLY=($(compgen -W "$_cantil_trust_opts" -- "$cur"))
                    else
                        _cantil_ports "$cur"
                    fi
                    ;;
            esac
            ;;

        provision-ca)
            case "$prev" in
                --trust)
                    COMPREPLY=($(compgen -W 'none pin ca ca+cn' -- "$cur"))
                    ;;
                --ca-dir)
                    _filedir -d
                    ;;
                --ca-cert|--client-cert|--client-chain)
                    _filedir '*.der'
                    ;;
                --cn|--o|--ou|--c|--st|--l|--validity|--path-len|--cn)
                    COMPREPLY=()
                    ;;
                *)
                    if [[ "$cur" == -* ]]; then
                        COMPREPLY=($(compgen -W \
                            '--new --cn --o --ou --c --st --l --validity --path-len
                             '"$_cantil_trust_opts" -- "$cur"))
                    else
                        _cantil_ports "$cur"
                    fi
                    ;;
            esac
            ;;

        sign-key-slot)
            case "$prev" in
                --trust)
                    COMPREPLY=($(compgen -W 'none pin ca ca+cn' -- "$cur"))
                    ;;
                --ca-dir)
                    _filedir -d
                    ;;
                --ca-cert|--client-cert|--client-chain)
                    _filedir '*.der'
                    ;;
                *)
                    if [[ "$cur" == -* ]]; then
                        COMPREPLY=($(compgen -W "$_cantil_trust_opts" -- "$cur"))
                    else
                        _cantil_ports "$cur"
                    fi
                    ;;
            esac
            ;;

        protect)
            case "$prev" in
                --trust)
                    COMPREPLY=($(compgen -W 'none pin ca ca+cn' -- "$cur"))
                    ;;
                --ca-dir)
                    _filedir -d
                    ;;
                --ca-cert|--client-cert|--client-chain)
                    _filedir '*.der'
                    ;;
                *)
                    if [[ "$cur" == -* ]]; then
                        COMPREPLY=($(compgen -W "--certs $_cantil_trust_opts" -- "$cur"))
                    else
                        _cantil_ports "$cur"
                    fi
                    ;;
            esac
            ;;

        unprotect|key-chain)
            case "$prev" in
                --trust)
                    COMPREPLY=($(compgen -W 'none pin ca ca+cn' -- "$cur"))
                    ;;
                --ca-dir)
                    _filedir -d
                    ;;
                --ca-cert|--client-cert|--client-chain)
                    _filedir '*.der'
                    ;;
                *)
                    if [[ "$cur" == -* ]]; then
                        COMPREPLY=($(compgen -W "$_cantil_trust_opts" -- "$cur"))
                    else
                        _cantil_ports "$cur"
                    fi
                    ;;
            esac
            ;;

        sign-csr-slot)
            case "$prev" in
                --trust)
                    COMPREPLY=($(compgen -W 'none pin ca ca+cn' -- "$cur"))
                    ;;
                --ca-dir)
                    _filedir -d
                    ;;
                --ca-cert|--client-cert|--client-chain)
                    _filedir '*.der'
                    ;;
                "$cmd")
                    # first positional after cmd = issuer_slot, nothing to complete
                    COMPREPLY=()
                    ;;
                *)
                    if [[ "$cur" == -* ]]; then
                        COMPREPLY=($(compgen -W "$_cantil_trust_opts" -- "$cur"))
                    elif [[ "$cur" == *.der* || "$cur" == /* ]]; then
                        _filedir '*.der'
                    else
                        # Could be a DER file or a port — offer both
                        _filedir '*.der'
                        _cantil_ports "$cur"
                    fi
                    ;;
            esac
            ;;

        session-sign)
            case "$prev" in
                --trust)
                    COMPREPLY=($(compgen -W 'none pin ca ca+cn' -- "$cur"))
                    ;;
                --ca-dir)
                    _filedir -d
                    ;;
                --ca-cert|--client-cert|--client-chain)
                    _filedir '*.der'
                    ;;
                *)
                    if [[ "$cur" == -* ]]; then
                        COMPREPLY=($(compgen -W "--force $_cantil_trust_opts" -- "$cur"))
                    else
                        _cantil_ports "$cur"
                    fi
                    ;;
            esac
            ;;

        session-push)
            case "$prev" in
                --trust)
                    COMPREPLY=($(compgen -W 'none pin ca ca+cn' -- "$cur"))
                    ;;
                --ca-dir)
                    _filedir -d
                    ;;
                --ca-cert|--chain|--client-cert|--client-chain)
                    _filedir '*.der'
                    ;;
                *)
                    if [[ "$cur" == -* ]]; then
                        COMPREPLY=($(compgen -W "--chain --force $_cantil_trust_opts" -- "$cur"))
                    elif [[ "$cur" == *.der* || "$cur" == /* || "$cur" == ./* ]]; then
                        _filedir '*.der'
                    else
                        # First positional = cert.der
                        _filedir '*.der'
                        _cantil_ports "$cur"
                    fi
                    ;;
            esac
            ;;

        unpair)
            case "$prev" in
                --trust)
                    COMPREPLY=($(compgen -W 'none pin ca ca+cn' -- "$cur"))
                    ;;
                --ca-dir)
                    _filedir -d
                    ;;
                --ca-cert|--client-cert|--client-chain)
                    _filedir '*.der'
                    ;;
                *)
                    if [[ "$cur" == -* ]]; then
                        COMPREPLY=($(compgen -W "$_cantil_trust_opts" -- "$cur"))
                    else
                        _cantil_ports "$cur"
                    fi
                    ;;
            esac
            ;;

        name)
            case "$prev" in
                --trust)
                    COMPREPLY=($(compgen -W 'none pin ca ca+cn' -- "$cur"))
                    ;;
                --ca-dir)
                    _filedir -d
                    ;;
                --ca-cert|--client-cert|--client-chain)
                    _filedir '*.der'
                    ;;
                *)
                    if [[ "$cur" == -* ]]; then
                        COMPREPLY=($(compgen -W "$_cantil_trust_opts" -- "$cur"))
                    else
                        _cantil_ports "$cur"
                    fi
                    ;;
            esac
            ;;
    esac
}

complete -F _cantil cantil
