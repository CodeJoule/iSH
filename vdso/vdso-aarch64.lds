ENTRY(__kernel_rt_sigreturn);

VERSION {
    LINUX_2.5 {
    global:
        __kernel_sigreturn;
        __kernel_rt_sigreturn;
    local: *;
    };

    LINUX_2.6 {
    global:
        __vdso_clock_gettime;
        __vdso_gettimeofday;
        __vdso_time;
    };
}

SECTIONS {
    . = SIZEOF_HEADERS;

	.hash          : {*(.hash)}            :text
    .dynsym        : {*(.dynsym)}
    .dynstr        : {*(.dynstr)}
    .gnu.version   : {*(.gnu.version)}
    .gnu.version_d : {*(.gnu.version_d)}
    .gnu.version_r : {*(.gnu.version_r)}

    .dynamic       : {*(.dynamic)}         :text :dynamic

    .rodata        : {
		*(.rodata*)
		*(.data*)
		*(.sdata*)
		*(.got.plt) *(.got)
		*(.gnu.linkonce.d.*)
		*(.bss*)
		*(.dynbss*)
		*(.gnu.linkonce.b.*)
    }                                      :text
    .note          : {*(.note.*)}          :text :note

    .eh_frame_hdr  : {*(.eh_frame_hdr)}    :text :eh_frame_hdr
    .eh_frame      : {KEEP (*(.eh_frame))} :text

    .text          : {*(.text*)}           :text

    /DISCARD/ : {
        *(.debug*)
        *(.comment)
    }
}

PHDRS {
	text         PT_LOAD    FLAGS(5) FILEHDR PHDRS;
	dynamic      PT_DYNAMIC FLAGS(4);
	note         PT_NOTE    FLAGS(4);
	eh_frame_hdr PT_GNU_EH_FRAME;
}
