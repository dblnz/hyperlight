use std::cmp::min;
use std::io::Write;

use super::gdb::X86_64Regs;
use elfcore::{ArchState, CoreDumpBuilder, CoreError, Elf64_Auxv, ReadProcessMemory};
use elfcore::{ProcessInformation, ThreadView, VaProtection, VaRegion};
use elfcore::Pid;
use tempfile::NamedTempFile;

use super::Hypervisor;
use crate::{mem::memory_region::{MemoryRegion, MemoryRegionFlags}, new_error, Result};

/// Dump registers + memory regions + raw memory to a tempfile
#[cfg(crashdump)]
pub(crate) fn crashdump_to_tempfile(hv: &dyn Hypervisor) -> Result<()> {
    let mut temp_file = NamedTempFile::with_prefix("mem")?;
    let hv_details = format!("{:#x?}", hv);

    // write hypervisor details such as registers, info about mapped memory regions, etc.
    temp_file.write_all(hv_details.as_bytes())?;
    temp_file.write_all(b"================ MEMORY DUMP =================\n")?;

    // write the raw memory dump for each memory region
    for region in hv.get_memory_regions() {
        if region.host_region.start == 0 || region.host_region.is_empty() {
            continue;
        }
        // SAFETY: we got this memory region from the hypervisor so should never be invalid
        let region_slice = unsafe {
            std::slice::from_raw_parts(
                region.host_region.start as *const u8,
                region.host_region.len(),
            )
        };
        temp_file.write_all(region_slice)?;
    }
    temp_file.flush()?;

    // persist the tempfile to disk
    let persist_path = temp_file.path().with_extension("dmp");
    temp_file
        .persist(&persist_path)
        .map_err(|e| new_error!("Failed to persist crashdump file: {:?}", e))?;

    println!("Memory dumped to file: {:?}", persist_path);
    log::error!("Memory dumped to file: {:?}", persist_path);

    crashdump_to_dumpfile(hv)?;

    Ok(())
}

struct GuestView {
    regions: Vec<VaRegion>,
    threads: Vec<ThreadView>,
    aux_vector: Vec<elfcore::Elf64_Auxv>,
}

impl GuestView {
    fn new(hv: &dyn Hypervisor) -> Self {
        let regions = hv.get_memory_regions()
            .iter()
            .filter(|r| !r.host_region.is_empty())
            .map(|r| 
                VaRegion {
                    begin: r.guest_region.start as u64,
                    end: r.guest_region.end as u64,
                    offset: r.host_region.start as u64,
                    protection: VaProtection {
                        is_private: false,
                        read: r.flags.contains(MemoryRegionFlags::READ),
                        write: r.flags.contains(MemoryRegionFlags::WRITE),
                        execute: r.flags.contains(MemoryRegionFlags::EXECUTE),
                    },
                    mapped_file_name: None,
                
            })
            .collect();

        let regs = hv.get_regs();
        let sregs = hv.get_sregs();
        let thread = ThreadView {
            flags: 0,    // Kernel flags for the process
            tid: Pid::from_raw(1),
            uid: 0,      // User ID
            gid: 0,      // Group ID
            comm: "(simpleguest)\0".to_string(),
            ppid: 0,     // Parent PID
            pgrp: 0,     // Process group ID
            nice: 0,     // Nice value
            state: 0,    // Process state
            utime: 0,    // User time
            stime: 0,    // System time
            cutime: 0,   // Children User time
            cstime: 0,   // Children User time
            cursig: 0,   // Current signal
            session: 0,  // Session ID of the process
            sighold: 0,  // Blocked signal
            sigpend: 0,  // Pending signal
            cmd_line: "hyperlight (simpleguest)\0".to_string(),

            arch_state: Box::new(ArchState {
                gpr_state: vec![
                    regs.r15,        // r15
                    regs.r14,        // r14
                    regs.r13,        // r13
                    regs.r12,        // r12
                    regs.rbp,        // rbp
                    regs.rbx,        // rbx
                    regs.r11,        // r11
                    regs.r10,        // r10
                    regs.r9,         // r9
                    regs.r8,         // r8
                    regs.rax,        // rax
                    regs.rcx,        // rcx
                    regs.rdx,        // rdx
                    regs.rsi,        // rsi
                    regs.rdi,        // rdi
                    0, // orig rax
                    regs.rip,        // rip
                    sregs.cs as u64, // cs
                    regs.rflags,     // eflags
                    regs.rsp,        // rsp
                    sregs.ss as u64, // ss
                    sregs.fs_base,   // fs_base
                    sregs.gs_base,   // gs_base
                    sregs.ds as u64, // ds
                    sregs.es as u64, // es
                    sregs.fs as u64, // fs
                    sregs.gs as u64, // gs
                ],
                components: vec![],
            }),

        };

        let auxv = vec![
            Elf64_Auxv {
                a_type: 9, // AT_ENTRY
                // Hardcoded value: 0x209000 - code offset
                // TODO: Add a method to retrieve this offset
                // NOTE: RIP is already offseted with this amount
                a_val:  regs.rip - 0x209000,
            }, 
            Elf64_Auxv {
                a_type: 0, // AT_NULL
                a_val: 0,
            },
        ];

        Self {
            regions,
            threads: vec![thread],
            aux_vector: auxv,
        }
    }
}

impl ProcessInformation for GuestView {
    fn get_pid(&self) -> Option<Pid> {
        Some(Pid::from_raw(1))
    }
    fn get_threads(&self) -> Option<&[elfcore::ThreadView]> {
        Some(&self.threads)
    }
    fn get_page_size(&self) -> usize {
        0x1000
    }
    fn get_aux_vector(&self) -> Option<&[elfcore::Elf64_Auxv]> {
        Some(&self.aux_vector)
    }
    fn get_va_regions(&self) -> &[elfcore::VaRegion] {
        &self.regions
    }
    fn get_mapped_files(&self) -> Option<&[elfcore::MappedFile]> {
        None
    }
}

struct GuestMemReader {
    regions: Vec<MemoryRegion>,
}

impl GuestMemReader {
    fn new(hv: &dyn Hypervisor) -> Self {
        Self {
            regions: hv.get_memory_regions().to_vec(),
        }
    }
}

impl ReadProcessMemory for GuestMemReader {
    fn read_process_memory(&mut self, base: usize, buf: &mut [u8]) -> std::result::Result<usize, CoreError> {
        let mut size = 0;

        for r in self.regions.iter() {
            if base >= r.guest_region.start && base < r.guest_region.end {
                let offset = base - r.guest_region.start;

                let region_slice = unsafe {
                    std::slice::from_raw_parts(
                        r.host_region.start as *const u8,
                        r.host_region.len(),
                    )
                };

                let start = offset;
                let end = offset + min(buf.len(), region_slice.len());
                buf.copy_from_slice(&region_slice[start..end]);
                size = end - start;
                break;
            }
        }
        
        std::result::Result::Ok(size)
    }
}

#[cfg(crashdump)]
pub(crate) fn crashdump_to_dumpfile(hv: &dyn Hypervisor) -> Result<()> {
    use std::fs::File;

    let gv = GuestView::new(hv);
    let memory_reader = GuestMemReader::new(hv);

    let cdb = CoreDumpBuilder::new(Box::new(gv) as Box<dyn ProcessInformation>, Box::new(memory_reader) as Box<dyn ReadProcessMemory>).map_err(|e| new_error!("ERROR: {:?}", e))?;
    let file = File::create("core_dump.elf")?;

    cdb
        .write(file)
        .map_err(|e| new_error!("Write Error: {:?}", e))?;

    Ok(())
}
