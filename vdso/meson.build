# VDSO build for guest architecture (i386 or aarch64).

clang = find_program('/usr/local/opt/llvm/bin/clang', '/opt/homebrew/opt/llvm/bin/clang', '/opt/local/bin/clang', 'clang')
check_cc = find_program('check-cc.sh')
result = run_command(check_cc, clang, check: false)
if result.returncode() != 0
    message('\n' + result.stdout() + result.stderr())
    if build_machine.system() == 'darwin'
        install_msg = 'Install LLVM through Homebrew (brew install llvm)'
    elif build_machine.system() == 'linux'
        install_msg = 'Install Clang and LLD using your package manager (e.g. sudo apt install clang lld)'
    endif
    error('Could not find usable VDSO compiler. ' + install_msg)
endif

guest_arch = get_option('guest_arch')
if guest_arch == 'aarch64'
    vdso_target = 'aarch64-linux'
    vdso_asm = 'vdso-aarch64.S'
    vdso_c = 'vdso-aarch64.c'
    vdso_lds = 'vdso-aarch64.lds'
else
    vdso_target = 'i386-linux'
    vdso_asm = 'vdso.S'
    vdso_c = 'vdso.c'
    vdso_lds = 'vdso.lds'
endif

vdso_compiler = [clang, '-target', vdso_target, '-fuse-ld=lld']

vdso = custom_target('vdso', input: [vdso_asm, vdso_c, vdso_lds], output: 'libvdso.so.elf',
    command: vdso_compiler + ['-o', '@OUTPUT@', '@INPUT0@', '@INPUT1@',
        '-nostdlib', '-Wl,-T,@INPUT2@', '-Wl,--hash-style,sysv', '-shared', '-fPIC']
        + get_option('vdso_c_args').split())
