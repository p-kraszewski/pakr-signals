/*

Copyright (c) 2020 Pawel Kraszewski. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted
provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice, this list of
       conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright notice, this list of
       conditions and the following disclaimer in the documentation and/or other materials
       provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

//! A set of tools wrapping Linux' [`libc::sigset_t`] functionality and supporting Rust-firendly
//! signals and pids definition.
//!
//! # Examples
//!
//! ```
//! use pakr_signals::*;
//!
//! // Create empty SigSet
//! let mut sigset = SigSet::new();
//!
//! // Add SIGUSR1 to SigSet
//! sigset.add(Sig::USR1);
//!
//! // Tests of presence
//!
//! // SIGUSR1 is present
//! assert!(sigset.has(Sig::USR1));
//!
//! // SIGUSR2 is not present
//! assert!(!sigset.has(Sig::USR2));
//!
//! // Has at least one of SIGUSR1/SIGUSR2
//! assert!(sigset.has_any(&[Sig::USR1,Sig::USR2]));
//!
//! // Doesn't have every of SIGUSR1/SIGUSR2
//! assert!(!sigset.has_all(&[Sig::USR1,Sig::USR2]));
//!
//! // Hide from runtime. SIGINT (aka ^C) won't be handled by runtime anymore (^C won't break the
//! // program). It may be then handled by user-defined handler down the code.
//!
//! let sigint = SigSet::from(&[Sig::INT]);
//! sigint.disable_default_handler().expect("Can't disable default handler for SIGINT");
//!
//! let my_pid =  Pid::own().expect("Cant't get own PID");
//!
//! // Send SIGINT to self (should be ignored)
//! Sig::INT.send_to(my_pid).expect("Can't send SIGINT");
//!
//! // other syntax:
//! my_pid.send(Sig::INT).expect("Can't send SIGINT");
//!
//! // Mark as processed by runtime. SIGQUIT (aka ^\) will be handled by runtime and would break the
//! // program with a core dump (if enabled in system).
//! //
//! // This is the default state - initally all signals are delivered to runtime, regardless of
//! // whether runtime ignores them (like SIGUSR1) or not (like SIGQUIT)
//! let sigquit = SigSet::from(&[Sig::QUIT]);
//! sigquit.enable_default_handler().expect("Can't enable default handler for SIGQUIT");
//! ```

use std::{io, mem::MaybeUninit};

use libc::{
    c_int, pid_t, pthread_sigmask, sigaddset, sigdelset, sigemptyset, sigfillset, sigismember, sigset_t,
};

#[cfg(not(target_os = "linux"))]
compile_error!("sigprocmask and friends are Linux-specific feature");

/// A wrapper for [`libc::pid_t`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Pid(pid_t);

impl Pid {
    /// Get current process' pid
    pub fn own() -> io::Result<Self> {
        let pid = unsafe { libc::getpid() };
        if pid == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(pid))
        }
    }

    /// Get parent process' pid
    pub fn parent() -> io::Result<Self> {
        let pid = unsafe { libc::getppid() };
        if pid == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(pid))
        }
    }

    /// Send signal to process
    pub fn send(self, sig: Sig) -> io::Result<()> {
        let pid = unsafe { libc::kill(self.0, sig.into()) };
        if pid == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl Into<pid_t> for Pid {
    /// Convert [`Pid`] to [`libc::pid_t`].
    #[inline]
    fn into(self) -> pid_t {
        self.0
    }
}

impl From<pid_t> for Pid {
    /// Convert [`libc::pid_t`] to [`Pid`].
    #[inline]
    fn from(pid: pid_t) -> Self {
        Self(pid)
    }
}

/// Linux signals
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum Sig {
    ABRT = libc::SIGABRT,
    ALRM = libc::SIGALRM,
    BUS = libc::SIGBUS,
    CHLD = libc::SIGCHLD,
    CONT = libc::SIGCONT,
    FPE = libc::SIGFPE,
    HUP = libc::SIGHUP,
    ILL = libc::SIGILL,
    INT = libc::SIGINT,
    KILL = libc::SIGKILL,
    PIPE = libc::SIGPIPE,
    POLL = libc::SIGPOLL,
    PROF = libc::SIGPROF,
    PWR = libc::SIGPWR,
    QUIT = libc::SIGQUIT,
    SEGV = libc::SIGSEGV,
    STKFLT = libc::SIGSTKFLT,
    STOP = libc::SIGSTOP,
    SYS = libc::SIGSYS,
    TERM = libc::SIGTERM,
    TSTP = libc::SIGTSTP,
    TTIN = libc::SIGTTIN,
    TTOU = libc::SIGTTOU,
    URG = libc::SIGURG,
    USR1 = libc::SIGUSR1,
    USR2 = libc::SIGUSR2,
    VTALRM = libc::SIGVTALRM,
    WINCH = libc::SIGWINCH,
    XCPU = libc::SIGXCPU,
    XFSZ = libc::SIGXFSZ,
}

/// Convert `Sig` to `i32` (for example to use with [`libc::*`] crate)
impl Into<i32> for Sig {
    #[inline]
    fn into(self) -> i32 {
        self as i32
    }
}

/// Convert `i32` to `Sig` for valid signals.
///
/// Panics if `sig` does not represent a valid signal.
impl From<i32> for Sig {
    #[inline]
    fn from(sig: i32) -> Self {
        match sig {
            libc::SIGABRT => Sig::ABRT,
            libc::SIGALRM => Sig::ALRM,
            libc::SIGBUS => Sig::BUS,
            libc::SIGCHLD => Sig::CHLD,
            libc::SIGCONT => Sig::CONT,
            libc::SIGFPE => Sig::FPE,
            libc::SIGHUP => Sig::HUP,
            libc::SIGILL => Sig::ILL,
            libc::SIGINT => Sig::INT,
            libc::SIGKILL => Sig::KILL,
            libc::SIGPIPE => Sig::PIPE,
            libc::SIGPOLL => Sig::POLL,
            libc::SIGPROF => Sig::PROF,
            libc::SIGPWR => Sig::PWR,
            libc::SIGQUIT => Sig::QUIT,
            libc::SIGSEGV => Sig::SEGV,
            libc::SIGSTKFLT => Sig::STKFLT,
            libc::SIGSTOP => Sig::STOP,
            libc::SIGSYS => Sig::SYS,
            libc::SIGTERM => Sig::TERM,
            libc::SIGTSTP => Sig::TSTP,
            libc::SIGTTIN => Sig::TTIN,
            libc::SIGTTOU => Sig::TTOU,
            libc::SIGURG => Sig::URG,
            libc::SIGUSR1 => Sig::USR1,
            libc::SIGUSR2 => Sig::USR2,
            libc::SIGVTALRM => Sig::VTALRM,
            libc::SIGWINCH => Sig::WINCH,
            libc::SIGXCPU => Sig::XCPU,
            libc::SIGXFSZ => Sig::XFSZ,
            s => panic!("Invalid signal {}", s),
        }
    }
}

impl Sig {
    /// Send [`Sig`]nal to process specified by [`libc::pid_t`].
    pub fn send_to(self, pid: Pid) -> io::Result<()> {
        pid.send(self)
    }
}

/// A wrapper for [`libc::sigset_t`]
pub struct SigSet(sigset_t);

impl SigSet {
    /// Create new, empty [`SigSet`]
    #[inline]
    pub fn new() -> Self {
        let mut u_sigset = MaybeUninit::<sigset_t>::uninit();
        let sigset = unsafe {
            sigemptyset(u_sigset.as_mut_ptr() as *mut sigset_t);
            u_sigset.assume_init()
        };

        SigSet(sigset)
    }

    /// Clear all signals in [`SigSet`]
    #[inline]
    pub fn clear(&mut self) -> &mut Self {
        unsafe {
            sigemptyset(&mut self.0);
        }
        self
    }

    /// Set all signals in [`SigSet`]
    #[inline]
    pub fn fill(&mut self) -> &mut Self {
        unsafe {
            sigfillset(&mut self.0);
        }
        self
    }

    /// Add a signle [`Sig`] to [`SigSet`].
    ///
    /// Re-adding already existing signal does nothing.
    #[inline]
    pub fn add(&mut self, sig: Sig) -> &mut Self {
        unsafe {
            sigaddset(&mut self.0, sig.into());
        }
        self
    }

    /// Add a list of [`Sig`]s to [`SigSet`].
    ///
    /// Re-adding already existing signals does nothing.
    pub fn add_many(&mut self, sigs: &[Sig]) -> &mut Self {
        for &sig in sigs {
            self.add(sig);
        }
        self
    }

    /// Remove a signle [`Sig`] from [`SigSet`].
    ///
    /// Removing already removed signal does nothing.
    #[inline]
    pub fn remove(&mut self, sig: Sig) -> &mut Self {
        unsafe {
            sigdelset(&mut self.0, sig.into());
        }
        self
    }

    /// Remove a list of [`Sig`]s from [`SigSet`].
    ///
    /// Removing already removed signals does nothing.
    pub fn remove_many(&mut self, sigs: &[Sig]) -> &mut Self {
        for &sig in sigs {
            self.remove(sig);
        }
        self
    }

    /// Check if [`Sig`]nal is present in [`SigSet`]
    #[inline]
    pub fn has(&self, sig: Sig) -> bool {
        match unsafe { sigismember(&self.0, sig.into()) } {
            1 => true,
            _ => false,
        }
    }

    /// Check if [`SigSet`] has any of [`Sig`]nals from the list set
    pub fn has_any(&self, sigs: &[Sig]) -> bool {
        for &sig in sigs {
            if self.has(sig) {
                return true;
            }
        }
        false
    }

    /// Check if [`SigSet`] has all of [`Sig`]nals from the list set
    pub fn has_all(&self, sigs: &[Sig]) -> bool {
        for &sig in sigs {
            if !self.has(sig) {
                return false;
            }
        }
        true
    }

    /// Detach [`SigSet`] from default handlers.
    ///
    /// Specified signals are ignored by runtime but can be handled by user-defined handlers, for
    /// example by [`mio-signalfd`].
    #[inline]
    pub fn disable_default_handler(&self) -> io::Result<()> {
        self.set_procmask(libc::SIG_BLOCK)
    }

    /// Attach a [`SigSet`] to default handlers.
    ///
    /// Specified signals are handled by runtime according to default rules, which may prevent
    /// signal from reaching user-defined handler.
    #[inline]
    pub fn enable_default_handler(&self) -> io::Result<()> {
        self.set_procmask(libc::SIG_UNBLOCK)
    }

    #[inline]
    fn set_procmask(&self, action: c_int) -> io::Result<()> {
        if unsafe { pthread_sigmask(action, self.as_ptr(), std::ptr::null_mut()) } == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Create [`SigSet`] pre-populated with list of [`Sig`]s
    pub fn from(sigs: &[Sig]) -> Self {
        let mut sigset = Self::new();
        sigset.add_many(sigs);
        sigset
    }

    /// Expose as const pointer to underlying [`libc::sigset_t`]
    #[inline]
    pub fn as_ptr(&self) -> *const sigset_t {
        &self.0
    }

    /// Expose as mut pointer to underlying [`libc::sigset_t`]
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut sigset_t {
        &mut self.0
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    /// All signals
    const SIG_ALL: &[Sig] = &[
        Sig::ABRT,
        Sig::ALRM,
        Sig::BUS,
        Sig::CHLD,
        Sig::CONT,
        Sig::FPE,
        Sig::HUP,
        Sig::ILL,
        Sig::INT,
        Sig::KILL,
        Sig::PIPE,
        Sig::POLL,
        Sig::PROF,
        Sig::PWR,
        Sig::QUIT,
        Sig::SEGV,
        Sig::STKFLT,
        Sig::STOP,
        Sig::SYS,
        Sig::TERM,
        Sig::TSTP,
        Sig::TTIN,
        Sig::TTOU,
        Sig::URG,
        Sig::USR1,
        Sig::USR2,
        Sig::VTALRM,
        Sig::WINCH,
        Sig::XCPU,
        Sig::XFSZ,
    ];

    #[test]
    fn all_signals() {
        let mut sigset = SigSet::new();

        assert!(!sigset.has_any(SIG_ALL));
        sigset.fill();
        assert!(sigset.has_all(SIG_ALL));
        sigset.clear();
        assert!(!sigset.has_any(SIG_ALL));
    }

    #[test]
    fn single_signal_all_any() {
        let sigset = SigSet::from(&[Sig::USR1]);
        assert!(sigset.has(Sig::USR1));
        assert!(sigset.has_any(SIG_ALL));
        assert!(!sigset.has_all(SIG_ALL));
    }

    #[test]
    fn single_signal() {
        let mut sigset = SigSet::new();

        for &sig in SIG_ALL {
            assert!(!sigset.has(sig));
            sigset.add(sig);
            assert!(sigset.has(sig));
            sigset.remove(sig);
            assert!(!sigset.has(sig));
        }
    }
}
