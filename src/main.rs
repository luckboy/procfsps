//
// Procfsps - Ps program with procfs crate.
// Copyright (C) 2022 Łukasz Szpakowski
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
use std::cmp::max;
use std::env;
use std::ffi::*;
use std::io::*;
use std::mem::MaybeUninit;
use std::process::*;
use std::time::SystemTime;
use getopt;
use getopt::Opt;
use procfs;
use users::get_user_by_name;
use users::get_group_by_name;
use users::get_user_by_uid;
use users::get_group_by_gid;

#[derive(Clone)]
pub struct Tm
{
    pub sec: i32,
    pub min: i32,
    pub hour: i32,
    pub mday: i32,
    pub mon: i32,
    pub year: i32,
    pub wday: i32,
    pub yday: i32,
    pub isdst: i32,
    pub gmtoff: i64,
    pub zone: Option<CString>,
}

#[derive(Copy, Clone)]
enum Field
{
    Addr,
    Args,
    C,
    Comm,
    ETime,
    Flags,
    GId,
    Group,
    Nice,
    PCPU,
    PGId,
    PId,
    PPId,
    Pri,
    RGId,
    RGroup,
    RUId,
    RUser,
    State,
    STime,
    Sz,
    Time,
    TTY,
    UId,
    User,
    VSz,
    WChan,
}

#[derive(Copy, Clone)]
enum FilterFlag
{
    None,
    AllWithTerminals,
    All,
    AllExpectSessionLeaders,
}

struct Options
{
    filter_flag: FilterFlag,
    real_uids: Option<Vec<u32>>,
    uids: Option<Vec<u32>>,
    real_gids: Option<Vec<u32>>,
    gids: Option<Vec<u32>>,
    pids: Option<Vec<i32>>,
    tty_nrs: Option<Vec<i32>>,
    fields_and_headers: Vec<(Field, String)>,
    full_listing_flag: bool,
}

enum Alignment
{
    Left,
    Right,
}

pub fn abbreviated_month_name(month: i32) -> Option<&'static str>
{
    match month {
        0  => Some("Jan"),
        1  => Some("Feb"),
        2  => Some("Mar"),
        3  => Some("Apr"),
        4  => Some("May"),
        5  => Some("Jun"),
        6  => Some("Jul"),
        7  => Some("Aug"),
        8  => Some("Sep"),
        9  => Some("Oct"),
        10 => Some("Nov"),
        11 => Some("Dec"),
        _  => None,
    }
}

pub fn localtime(time: i64) -> Result<Tm>
{
    let mut libc_tm: libc::tm = unsafe { MaybeUninit::uninit().assume_init() };
    let libc_time = time as libc::time_t;
    let res = unsafe { libc::localtime_r(&libc_time as *const libc::time_t, &mut libc_tm as *mut libc::tm) };
    if !res.is_null() {
        let zone = if !libc_tm.tm_zone.is_null() {
            let zone_cstr = unsafe { CStr::from_ptr(libc_tm.tm_zone) };
            Some(CString::new(zone_cstr.to_bytes()).unwrap())
        } else {
            None
        };
        let tm = Tm {
            sec: libc_tm.tm_sec,
            min: libc_tm.tm_min,
            hour: libc_tm.tm_hour,
            mday: libc_tm.tm_mday,
            mon: libc_tm.tm_mon,
            year: libc_tm.tm_year,
            wday: libc_tm.tm_wday,
            yday: libc_tm.tm_yday,
            isdst: libc_tm.tm_isdst,
            gmtoff: libc_tm.tm_gmtoff as i64,
            zone,
        };
        Ok(tm)
    } else {
        Err(Error::last_os_error())
    }
}

fn clear_filter_lists(opts: &mut Options)
{
    opts.real_uids = None;
    opts.uids = None;
    opts.real_gids = None;
    opts.gids = None;
    opts.pids = None;
    opts.tty_nrs = None;
}

fn parse_users(s: &String) -> Option<Vec<u32>>
{
    let mut uids: Vec<u32> = Vec::new();
    for t in s.split(|c: char| { c.is_whitespace() || c == ','}) {
        match t.parse::<u32>() {
            Ok(uid) => uids.push(uid),
            Err(_)  => {
                match get_user_by_name(t) {
                    Some(user) => uids.push(user.uid() as u32),
                    None       => {
                        eprintln!("Invalid user");
                        return None;
                    },
                }
            },
        }
    }
    Some(uids)
}

fn parse_groups(s: &String) -> Option<Vec<u32>>
{
    let mut gids: Vec<u32> = Vec::new();
    for t in s.split(|c: char| { c.is_whitespace() || c == ','}) {
        match t.parse::<u32>() {
            Ok(gid) => gids.push(gid),
            Err(_)  => {
                match get_group_by_name(t) {
                    Some(group) => gids.push(group.gid() as u32),
                    None        => {
                        eprintln!("Invalid user");
                        return None;
                    },
                }
            },
        }
    }
    Some(gids)
}

fn parse_pids(s: &String) -> Option<Vec<i32>>
{
    let mut pids: Vec<i32> = Vec::new();
    for t in s.split(|c: char| { c.is_whitespace() || c == ','}) {
        match t.parse::<i32>() {
            Ok(pid) => pids.push(pid),
            Err(err)  => {
                eprintln!("Invalid pid: {}", err);
                return None;
            },
        }
    }
    Some(pids)
}

fn parse_ttys(s: &String) -> Option<Vec<i32>>
{
    let mut tty_nrs: Vec<i32> = Vec::new();
    for t in s.split(|c: char| { c.is_whitespace() || c == ','}) {
        if t == "console" {
            tty_nrs.push(libc::makedev(5, 1) as i32);
        } else if t == "tty" {
            tty_nrs.push(libc::makedev(5, 0) as i32);
        } else if t == "pts/ptmx" {
            tty_nrs.push(libc::makedev(5, 2) as i32);
        } else if t.starts_with("ttyS") {
            match t[4..].parse::<u32>() {
                Ok(n) => {
                    if n <= 191 {
                        tty_nrs.push(libc::makedev(4, 64 + n) as i32);
                    } else {
                        println!("Invlaid terminal name");
                        return None;
                    }
                },
                Err(_) => {
                    println!("Invlaid terminal name");
                    return None;
                },
            }
        } else if t.starts_with("tty") {
            match t[3..].parse::<u32>() {
                Ok(n) => {
                    if n <= 63 {
                        tty_nrs.push(libc::makedev(4, n) as i32);
                    } else {
                        println!("Invlaid terminal name");
                        return None;
                    }
                },
                Err(_) => {
                    println!("Invlaid terminal name");
                    return None;
                },
            }
        } else if t.starts_with("pts/") {
            match t[4..].parse::<u32>() {
                Ok(n) => {
                    if n <= 255 {
                        tty_nrs.push(libc::makedev(136, n) as i32);
                    } else {
                        println!("Invlaid terminal name");
                        return None;
                    }
                },
                Err(_) => {
                    println!("Invlaid terminal name");
                    return None;
                },
            }
        } else {
            println!("Invlaid terminal name");
            return None;
        }
    }
    Some(tty_nrs)
}

fn parse_fields_and_headers(s: &String) -> Option<Vec<(Field, String)>>
{
    let mut fields_and_headers: Vec<(Field, String)> = Vec::new();
    for t in s.split(|c: char| { c.is_whitespace() || c == ','}) {
        let (field_spec, header) = match t.split_once('=') {
            Some((field_spec, header)) => (field_spec, Some(header)),
            None => (t, None),
        };
        if field_spec == "addr" {
            fields_and_headers.push((Field::Addr, String::from(header.unwrap_or("ADDR"))));
        } else if field_spec == "args" {
            fields_and_headers.push((Field::Args, String::from(header.unwrap_or("COMMAND"))));
        } else if field_spec == "c" {
            fields_and_headers.push((Field::C, String::from(header.unwrap_or("C"))));
        } else if field_spec == "comm" {
            fields_and_headers.push((Field::Comm, String::from(header.unwrap_or("COMMAND"))));
        } else if field_spec == "etime" {
            fields_and_headers.push((Field::ETime, String::from(header.unwrap_or("ELAPSED"))));
        } else if field_spec == "flags" || field_spec == "f" {
            fields_and_headers.push((Field::Flags, String::from(header.unwrap_or("F"))));
        } else if field_spec == "gid" {
            fields_and_headers.push((Field::GId, String::from(header.unwrap_or("GID"))));
        } else if field_spec == "group" {
            fields_and_headers.push((Field::Group, String::from(header.unwrap_or("GROUP"))));
        } else if field_spec == "nice" {
            fields_and_headers.push((Field::Nice, String::from(header.unwrap_or("NI"))));
        } else if field_spec == "pcpu" {
            fields_and_headers.push((Field::PCPU, String::from(header.unwrap_or("%CPU"))));
        } else if field_spec == "pgid" {
            fields_and_headers.push((Field::PGId, String::from(header.unwrap_or("PGID"))));
        } else if field_spec == "pid" {
            fields_and_headers.push((Field::PId, String::from(header.unwrap_or("PID"))));
        } else if field_spec == "ppid" {
            fields_and_headers.push((Field::PPId, String::from(header.unwrap_or("PPID"))));
        } else if field_spec == "pri" {
            fields_and_headers.push((Field::Pri, String::from(header.unwrap_or("PRI"))));
        } else if field_spec == "rgid" {
            fields_and_headers.push((Field::RGId, String::from(header.unwrap_or("RGID"))));
        } else if field_spec == "rgroup" {
            fields_and_headers.push((Field::RGroup, String::from(header.unwrap_or("RGROUP"))));
        } else if field_spec == "ruid" {
            fields_and_headers.push((Field::RUId, String::from(header.unwrap_or("RUID"))));
        } else if field_spec == "ruser" {
            fields_and_headers.push((Field::RUser, String::from(header.unwrap_or("RUSER"))));
        } else if field_spec == "state" || field_spec == "s" {
            fields_and_headers.push((Field::State, String::from(header.unwrap_or("S"))));
        } else if field_spec == "stime" {
            fields_and_headers.push((Field::STime, String::from(header.unwrap_or("STIME"))));
        } else if field_spec == "sz" {
            fields_and_headers.push((Field::Sz, String::from(header.unwrap_or("SZ"))));
        } else if field_spec == "time" {
            fields_and_headers.push((Field::Time, String::from(header.unwrap_or("TIME"))));
        } else if field_spec == "tty" {
            fields_and_headers.push((Field::TTY, String::from(header.unwrap_or("TT"))));
        } else if field_spec == "uid" {
            fields_and_headers.push((Field::UId, String::from(header.unwrap_or("UID"))));
        } else if field_spec == "user" {
            fields_and_headers.push((Field::User, String::from(header.unwrap_or("USER"))));
        } else if field_spec == "vsz" {
            fields_and_headers.push((Field::VSz, String::from(header.unwrap_or("VSZ"))));
        } else if field_spec == "wchan" {
            fields_and_headers.push((Field::WChan, String::from(header.unwrap_or("WCHAN"))));
        } else {
            eprintln!("Invalid field");
            return None;
        }
    }
    Some(fields_and_headers)
}

fn filter(process: &procfs::process::Process, stat: &Option<procfs::process::Stat>, status: &Option<procfs::process::Status>, myself_tty_nr: i32, opts: &Options) -> bool
{
    let mut b = match opts.filter_flag {
        FilterFlag::None                    => {
            match stat {
                Some(stat) => stat.tty_nr == myself_tty_nr,
                None       => false,
            }
        },
        FilterFlag::AllWithTerminals        => {
            match stat {
                Some(stat) => {
                    let major = unsafe { libc::major(stat.tty_nr as libc::dev_t) };
                    let minor = unsafe { libc::minor(stat.tty_nr as libc::dev_t) };
                    (major == 4 && minor <= 255) || (major == 5 && (minor == 0 || minor == 1 || minor == 2)) || (major == 136 && minor <= 255) && process.pid != stat.session
                },
                None       => false,
            }
        },
        FilterFlag::All                     => true,
        FilterFlag::AllExpectSessionLeaders => {
            match stat {
                Some(stat) => {
                    process.pid != stat.session
                },
                None       => false,
            }
        },
    };
    let mut b2 = false;
    match &opts.real_uids {
        Some(uids) => {
            b2 |= match status {
                Some(status) => uids.contains(&status.ruid),
                None         => false,
            };
        },
        None       => (),
    };
    match &opts.uids {
        Some(uids) => {
            b2 |= match status {
                Some(status) => uids.contains(&status.euid),
                None         => false,
            };
        },
        None       => (),
    }
    match &opts.real_gids {
        Some(gids) => {
            b2 |= match status {
                Some(status) => gids.contains(&status.rgid),
                None         => false,
            };
        },
        None       => (),
    }
    match &opts.gids {
         Some(gids) => {
            b2 |= match status {
                Some(status) => gids.contains(&status.egid),
                None         => false,
            };
        },
        None       => (),
    }
    match &opts.pids {
        Some(pids) => b2 |= pids.contains(&process.pid),
        None       => (),
    }
    match &opts.tty_nrs {
        Some(tty_nrs) => {
            b2 |= match stat {
                Some(stat) => tty_nrs.contains(&stat.tty_nr),
                None       => false,
            };
        },
        None          => (),
    };
    if opts.real_uids.is_some() || opts.uids.is_some() || opts.real_gids.is_some() || opts.gids.is_some() || opts.pids.is_some() || opts.tty_nrs.is_some() {
        b &= b2;
    }
    b
}

fn time_to_string(secs: u64, is_etime: bool) -> String
{
    let sec = secs % 60;
    let min = (secs / 60) % 60;
    let hour = ((secs / 60) / 60) % 24;
    let days = ((secs / 60) / 60) / 24;
    if days > 0 {
        format!("{}-{:02}:{:02}:{:02}", days, hour, min, sec)
    } else {
        if !is_etime || hour > 0 {
            format!("{:02}:{:02}:{:02}", hour, min, sec)
        } else {
            format!("{:02}:{:02}", min, sec)
        }
    }
}

fn to_pcpu(stat: &Option<procfs::process::Stat>, uptime: f64, ticks_per_sec: u64) -> Option<u32>
{
    match stat {
        Some(stat) => {
            let total_time = stat.stime + stat.utime;
            let secs = (uptime as u64) + (stat.starttime / ticks_per_sec);
            Some(((((total_time / ticks_per_sec) * 100) / secs)) as u32)
        },
        None => None,
    }
}

fn print_string_with_width(s: &String, width: usize, align: Alignment, is_last: bool)
{
    match align {
        Alignment::Left  => {
            if !is_last {
                print!("{:<width$}", s, width = width);
            } else {
                print!("{}", s);
            }
        },
        Alignment::Right => print!("{:>width$}", s, width = width),
    }
}

fn print_header(field: Field, header: &String, opts: &Options, is_last: bool)
{
    let header_len = header.chars().fold(0, |x, _| x + 1);
    match field {
        Field::Addr => print_string_with_width(header, max(4, header_len), Alignment::Right, is_last),
        Field::Args => print_string_with_width(header, max(27, header_len), Alignment::Left, is_last),
        Field::C => print_string_with_width(header, max(3, header_len), Alignment::Right, is_last),
        Field::Comm => print_string_with_width(header, max(15, header_len), Alignment::Left, is_last),
        Field::ETime => print_string_with_width(header, max(11, header_len), Alignment::Right, is_last),
        Field::Flags => print_string_with_width(header, max(1, header_len), Alignment::Right, is_last),
        Field::GId => print_string_with_width(header, max(5, header_len), Alignment::Right, is_last),
        Field::Group => print_string_with_width(header, max(8, header_len), Alignment::Left, is_last),
        Field::Nice => print_string_with_width(header, max(3, header_len), Alignment::Right, is_last),
        Field::PCPU => print_string_with_width(header, max(4, header_len), Alignment::Right, is_last),
        Field::PGId => print_string_with_width(header, max(5, header_len), Alignment::Right, is_last),
        Field::PId => print_string_with_width(header, max(5, header_len), Alignment::Right, is_last),
        Field::PPId => print_string_with_width(header, max(5, header_len), Alignment::Right, is_last),
        Field::Pri => print_string_with_width(header, max(3, header_len), Alignment::Right, is_last),
        Field::RGId => print_string_with_width(header, max(5, header_len), Alignment::Right, is_last),
        Field::RGroup => print_string_with_width(header, max(8, header_len), Alignment::Left, is_last),
        Field::RUId => print_string_with_width(header, max(5, header_len), Alignment::Right, is_last),
        Field::RUser => print_string_with_width(header, max(8, header_len), Alignment::Left, is_last),
        Field::State => print_string_with_width(header, max(1, header_len), Alignment::Right, is_last),
        Field::STime => print_string_with_width(header, max(5, header_len), Alignment::Right, is_last),
        Field::Sz => print_string_with_width(header, max(6, header_len), Alignment::Right, is_last),
        Field::Time => print_string_with_width(header, max(11, header_len), Alignment::Right, is_last),
        Field::TTY => print_string_with_width(header, max(8, header_len), Alignment::Left, is_last),
        Field::UId => {
            if opts.full_listing_flag {
                print_string_with_width(header, max(8, header_len), Alignment::Left, is_last);
            } else {
                print_string_with_width(header, max(5, header_len), Alignment::Right, is_last);
            }
        },
        Field::User => print_string_with_width(header, max(8, header_len), Alignment::Left, is_last),
        Field::VSz => print_string_with_width(header, max(6, header_len), Alignment::Right, is_last),
        Field::WChan => print_string_with_width(header, max(8, header_len), Alignment::Left, is_last),
    }
}

fn print_headers(fields_and_headers: &[(Field, String)], opts: &Options)
{
    let len = fields_and_headers.len();
    let mut is_first = true;
    for (i, (field, header)) in fields_and_headers.iter().enumerate() {
        if !is_first {
            print!(" ");
        }
        print_header(*field, header, opts, i == len - 1);
        is_first = false;
    }
    println!("");
}

fn print_field(field: Field, header: &String, process: &procfs::process::Process, cmdline: &Option<Vec<String>>, stat: &Option<procfs::process::Stat>, status: &Option<procfs::process::Status>, wchan: &Option<String>, boot_time_secs: u64, uptime: f64, ticks_per_sec: u64, current_tm: &Tm, opts: &Options, is_last: bool)
{
    let header_len = header.chars().fold(0, |x, _| x + 1);
    match field {
        Field::Addr => print_string_with_width(&String::from("-"), max(4, header_len), Alignment::Right, is_last),
        Field::Args => {
            let comm = match cmdline {
                Some(cmdline) => cmdline.join(" "),
                None          => String::from("?"),
            };
            let state = match status {
                Some(status) => Some(status.state.clone()),
                None         => None,
            };
            let s = match state {
                Some(state) if state.starts_with("Z") => format!("{} <defunct>", comm),
                _ => format!("{}", comm),
            };
            print_string_with_width(&s, max(27, header_len), Alignment::Left, is_last);
        },
        Field::C => {
            let s = match to_pcpu(stat, uptime, ticks_per_sec) {
                Some(pcpu) => format!("{}", pcpu),
                None       => String::from("?"),
            };
            print_string_with_width(&s, max(3, header_len), Alignment::Right, is_last);
        },
        Field::Comm => {
            let comm = match stat {
                Some(stat) => stat.comm.clone(),
                None       => String::from("?"),
            };
            let state = match status {
                Some(status) => Some(status.state.clone()),
                None         => None,
            };
            let s = match state {
                Some(state) if state.starts_with("Z") => format!("{} <defunct>", comm),
                _ => format!("{}", comm),
            };
            print_string_with_width(&s, max(15, header_len), Alignment::Left, is_last);
        },
        Field::ETime => {
            let s = match stat {
                Some(stat) => time_to_string((uptime as u64).saturating_sub(stat.starttime / ticks_per_sec), true),
                None       => String::from("?"),
            };
            print_string_with_width(&s, max(11, header_len), Alignment::Right, is_last);
        },
        Field::Flags => {
            let s = match stat {
                Some(stat) => format!("{:o}", (stat.flags >> 6) & 7),
                None       => String::from("?"),
            };
            print_string_with_width(&s, max(1, header_len), Alignment::Right, is_last);
        },
        Field::GId => {
            let s = match status {
                Some(status) => format!("{}", status.egid),
                None         => String::from("?"),
            };
            print_string_with_width(&s, max(5, header_len), Alignment::Right, is_last);
        },
        Field::Group => {
            let s = match status {
                Some(status) => {
                    match get_group_by_gid(status.egid) {
                        Some(group) => group.name().to_string_lossy().into_owned(),
                        None        => format!("{}", status.egid),
                    }
                },
                None         => String::from("?"),
            };
            print_string_with_width(&s, max(8, header_len), Alignment::Left, is_last);
        },
        Field::Nice => {
            let s = match stat {
                Some(stat) => format!("{}", stat.nice),
                None       => String::from("?"),
            };
            print_string_with_width(&s, max(3, header_len), Alignment::Right, is_last);
        },
        Field::PCPU => {
            let s = match to_pcpu(stat, uptime, ticks_per_sec) {
                Some(pcpu) => format!("{}", pcpu),
                None       => String::from("?"),
            };
            print_string_with_width(&s, max(4, header_len), Alignment::Right, is_last);
        },
        Field::PGId => {
            let s = match stat {
                Some(stat) => format!("{}", stat.pgrp),
                None         => String::from("?"),
            };
            print_string_with_width(&s, max(5, header_len), Alignment::Right, is_last);
        },
        Field::PId => {
            let s = format!("{}", process.pid);
            print_string_with_width(&s, max(5, header_len), Alignment::Right, is_last);
        },
        Field::PPId => {
            let s = match stat {
                Some(stat) => format!("{}", stat.ppid),
                None       => String::from("?"),
            };
            print_string_with_width(&s, max(5, header_len), Alignment::Right, is_last);
        },
        Field::Pri => {
            let s = match stat {
                Some(stat) => format!("{}", stat.priority),
                None       => String::from("?"),
            };
            print_string_with_width(&s, max(3, header_len), Alignment::Right, is_last);
        },
        Field::RGId => {
            let s = match status {
                Some(status) => format!("{}", status.rgid),
                None         => String::from("?"),
            };
            print_string_with_width(&s, max(5, header_len), Alignment::Right, is_last)
        },
        Field::RGroup => {
            let s = match status {
                Some(status) => {
                    match get_group_by_gid(status.rgid) {
                        Some(group) => group.name().to_string_lossy().into_owned(),
                        None        => format!("{}", status.rgid),
                    }
                },
                None         => String::from("?"),
            };
            print_string_with_width(&s, max(8, header_len), Alignment::Left, is_last);
        },
        Field::RUId => {
            let s = match status {
                Some(status) => format!("{}", status.ruid),
                None         => String::from("?"),
            };
            print_string_with_width(&s, max(5, header_len), Alignment::Right, is_last)
        },
        Field::RUser => {
            let s = match status {
                Some(status) => {
                    match get_user_by_uid(status.ruid) {
                        Some(user) => user.name().to_string_lossy().into_owned(),
                        None       => format!("{}", status.ruid),
                    }
                },
                None         => String::from("?"),
            };
            print_string_with_width(&s, max(8, header_len), Alignment::Left, is_last);
        },
        Field::State => {
            let s = match status {
                Some(status) => format!("{}", status.state.chars().next().unwrap_or('?')),
                None         => String::from("?"),
            };
            print_string_with_width(&s, max(1, header_len), Alignment::Right, is_last);
        },
        Field::STime => {
            let s = match stat {
                Some(stat) => {
                    match localtime((boot_time_secs + stat.starttime / ticks_per_sec) as i64) {
                        Ok(tm) => {
                            if tm.year != current_tm.year {
                                format!("{}", current_tm.year + 1900)
                            } else if tm.yday != current_tm.yday {
                                format!("{}{:02}", abbreviated_month_name(current_tm.mon).unwrap_or("Unk"), tm.mday)
                            } else {
                                format!("{:02}:{:02}", tm.hour, tm.min)
                            }
                        },
                        Err(_) => {
                            format!("{}", stat.starttime / ticks_per_sec)
                        },
                    }
                },
                None => String::from("?"),
            };
            print_string_with_width(&s, max(5, header_len), Alignment::Right, is_last);
        },
        Field::Sz => {
            let s = match stat {
                Some(stat) => format!("{}", (stat.vsize.saturating_add(511)) / 512),
                None       => String::from("?"),
            };
            print_string_with_width(&s, max(6, header_len), Alignment::Right, is_last)
        },
        Field::Time => {
            let s = match stat {
                Some(stat) => time_to_string((stat.stime + stat.utime) / ticks_per_sec, false),
                None       => String::from("?"),
            };
            print_string_with_width(&s, max(11, header_len), Alignment::Right, is_last);
        },
        Field::TTY => {
            let s = match stat {
                Some(stat) => {
                    let major = unsafe { libc::major(stat.tty_nr as libc::dev_t) };
                    let minor = unsafe { libc::minor(stat.tty_nr as libc::dev_t) };
                    if major == 5 && minor == 1 {
                        String::from("console")
                    } else if major == 5 && minor == 0 {
                        String::from("tty")
                    } else if major == 5 && minor == 2 {
                        String::from("pts/ptmx")
                    } else if major == 4 && minor <= 63 {
                        format!("tty{}", minor)
                    } else if major == 4 && minor >= 64 &&  minor <= 255 {
                        format!("ttyS{}", minor - 64)
                    } else if major == 136 && minor <= 255 {
                        format!("pts/{}", minor)
                    } else {
                        String::from("?")
                    }
                },
                None       => String::from("?"),
            };
            print_string_with_width(&s, max(8, header_len), Alignment::Left, is_last);
        },
        Field::UId => {
            if opts.full_listing_flag {
                let s = match status {
                    Some(status) => {
                        match get_user_by_uid(status.euid) {
                            Some(user) => user.name().to_string_lossy().into_owned(),
                            None       => format!("{}", status.euid),
                        }
                    },
                    None         => String::from("?"),
                };
                print_string_with_width(&s, max(8, header_len), Alignment::Left, is_last);
            } else {
                let s = match status {
                    Some(status) => format!("{}", status.euid),
                    None         => String::from("?"),
                };
                print_string_with_width(&s, max(5, header_len), Alignment::Right, is_last);
            }
        },
        Field::User => {
            let s = match status {
                Some(status) => {
                    match get_user_by_uid(status.euid) {
                        Some(user) => user.name().to_string_lossy().into_owned(),
                        None       => format!("{}", status.euid),
                    }
                },
                None         => String::from("?"),
            };
            print_string_with_width(&s, max(8, header_len), Alignment::Left, is_last)
        },
        Field::VSz => {
            let s = match stat {
                Some(stat) => format!("{}", (stat.vsize.saturating_add(1023)) / 1024),
                None       => String::from("?"),
            };
            print_string_with_width(&s, max(6, header_len), Alignment::Right, is_last);
        },
        Field::WChan => {
            let s = match wchan {
                Some(wchan) => {
                    let wchan_len = wchan.chars().fold(0, |x, _| x + 1);
                    let u = if wchan_len > 8 {
                        let t: String = wchan.chars().take(8).collect();
                        t
                    } else {
                        wchan.clone()
                    };
                    if u != String::from("0") {
                        u
                    } else {
                        String::from("-")
                    }
                },
                None        => String::from("?"),
            };
            print_string_with_width(&s, max(8, header_len), Alignment::Left, is_last);
        },
    }
}

fn print_fields(fields_and_headers: &[(Field, String)], process: &procfs::process::Process, cmdline: &Option<Vec<String>>, stat: &Option<procfs::process::Stat>, status: &Option<procfs::process::Status>, wchan: &Option<String>, boot_time_secs: u64, uptime: f64, tick_per_sec: u64, current_tm: &Tm, opts: &Options)
{
    let len = fields_and_headers.len();
    let mut is_first = true;
    for (i, (field, header)) in fields_and_headers.iter().enumerate() {
        if !is_first {
            print!(" ");
        }
        print_field(*field, header, process, cmdline, stat, status, wchan, boot_time_secs, uptime, tick_per_sec, current_tm, opts, i == len - 1);
        is_first = false;
    }
    println!("");
}

fn main()
{
    let args: Vec<String> = env::args().collect();
    let mut opt_parser = getopt::Parser::new(&args, "AadefG:g:lo:p:t:U:u:");
    let mut opts = Options {
        filter_flag: FilterFlag::None,
        real_uids: None,
        uids: None,
        real_gids: None,
        gids: None,
        pids: None,
        tty_nrs: None,
        fields_and_headers: vec![
            (Field::PId, String::from("PID")),
            (Field::TTY, String::from("TTY")),
            (Field::Time, String::from("TIME")),
            (Field::Comm, String::from("CMD"))
        ],
        full_listing_flag: false,
    };
    loop {
        match opt_parser.next() {
            Some(Ok(Opt('A', _))) => {
                opts.filter_flag = FilterFlag::All;
                clear_filter_lists(&mut opts);
            },
            Some(Ok(Opt('a', _))) => {
                opts.filter_flag = FilterFlag::AllWithTerminals;
                clear_filter_lists(&mut opts);
            },
            Some(Ok(Opt('d', _))) => {
                opts.filter_flag = FilterFlag::AllExpectSessionLeaders;
                clear_filter_lists(&mut opts);
            },
            Some(Ok(Opt('e', _))) => {
                opts.filter_flag = FilterFlag::All;
                clear_filter_lists(&mut opts);
            },
            Some(Ok(Opt('f', _))) => {
                opts.fields_and_headers = vec![
                    (Field::UId, String::from("UID")),
                    (Field::PId, String::from("PID")),
                    (Field::PPId, String::from("PPID")),
                    (Field::C, String::from("C")),
                    (Field::STime, String::from("STIME")),
                    (Field::TTY, String::from("TTY")),
                    (Field::Time, String::from("TIME")),
                    (Field::Comm, String::from("CMD"))
                ];
                opts.full_listing_flag = true;
            },
            Some(Ok(Opt('G', Some(opt_arg)))) => {
                opts.filter_flag = FilterFlag::All;
                match parse_groups(&opt_arg) {
                    Some(gids) => {
                        let mut gids2 = match opts.real_gids {
                            Some(tmp_gids) => tmp_gids,
                            None           => Vec::new(),
                        };
                        gids2.extend(gids);
                        opts.real_gids = Some(gids2);
                    },
                    None => exit(1),
                }
            },
            Some(Ok(Opt('G', None))) => {
                eprintln!("option requires an argument -- 'G'");
                exit(1);
            },
            Some(Ok(Opt('g', Some(opt_arg)))) => {
                opts.filter_flag = FilterFlag::All;
                match parse_groups(&opt_arg) {
                    Some(gids) => {
                        let mut gids2 = match opts.gids {
                            Some(tmp_gids) => tmp_gids,
                            None           => Vec::new(),
                        };
                        gids2.extend(gids);
                        opts.gids = Some(gids2);
                    },
                    None => exit(1),
                }
            },
            Some(Ok(Opt('g', None))) => {
                eprintln!("option requires an argument -- 'g'");
                exit(1);
            },
            Some(Ok(Opt('l', _))) => {
                opts.fields_and_headers = vec![
                    (Field::Flags, String::from("F")),
                    (Field::State, String::from("S")),
                    (Field::UId, String::from("UID")),
                    (Field::PId, String::from("PID")),
                    (Field::PPId, String::from("PPID")),
                    (Field::C, String::from("C")),
                    (Field::Pri, String::from("PRI")),
                    (Field::Nice, String::from("NI")),
                    (Field::Addr, String::from("ADDR")),
                    (Field::Sz, String::from("SZ")),
                    (Field::WChan, String::from("WCHAN")),
                    (Field::TTY, String::from("TTY")),
                    (Field::Time, String::from("TIME")),
                    (Field::Comm, String::from("CMD"))
                ];
            },
            Some(Ok(Opt('o', Some(opt_arg)))) => {
                match parse_fields_and_headers(&opt_arg) {
                    Some(fields_and_headers) => opts.fields_and_headers = fields_and_headers,
                    None => exit(1),
                }
            },
            Some(Ok(Opt('o', None))) => {
                eprintln!("option requires an argument -- 'o'");
                exit(1);
            },
            Some(Ok(Opt('p', Some(opt_arg)))) => {
                opts.filter_flag = FilterFlag::All;
                match parse_pids(&opt_arg) {
                    Some(pids) => {
                        let mut pids2 = match opts.pids {
                            Some(tmp_pids) => tmp_pids,
                            None           => Vec::new(),
                        };
                        pids2.extend(pids);
                        opts.pids = Some(pids2);
                    },
                    None => exit(1),
                }
            },
            Some(Ok(Opt('p', None))) => {
                eprintln!("option requires an argument -- 'p'");
                exit(1);
            },
            Some(Ok(Opt('t', Some(opt_arg)))) => {
                opts.filter_flag = FilterFlag::All;
                match parse_ttys(&opt_arg) {
                    Some(tty_nrs) => {
                        let mut tty_nrs2 = match opts.tty_nrs {
                            Some(tmp_tty_nrs) => tmp_tty_nrs,
                            None           => Vec::new(),
                        };
                        tty_nrs2.extend(tty_nrs);
                        opts.tty_nrs = Some(tty_nrs2);
                    },
                    None => exit(1),
                }
            },
            Some(Ok(Opt('t', None))) => {
                eprintln!("option requires an argument -- 't'");
                exit(1);
            },
            Some(Ok(Opt('U', Some(opt_arg)))) => {
                opts.filter_flag = FilterFlag::All;
                match parse_users(&opt_arg) {
                    Some(uids) => {
                        let mut uids2 = match opts.real_uids {
                            Some(tmp_uids) => tmp_uids,
                            None           => Vec::new(),
                        };
                        uids2.extend(uids);
                        opts.real_uids = Some(uids2);
                    },
                    None => exit(1),
                }
            },
            Some(Ok(Opt('U', None))) => {
                eprintln!("option requires an argument -- 'U'");
                exit(1);
            },
            Some(Ok(Opt('u', Some(opt_arg)))) => {
                opts.filter_flag = FilterFlag::All;
                match parse_users(&opt_arg) {
                    Some(uids) => {
                        let mut uids2 = match opts.uids {
                            Some(tmp_uids) => tmp_uids,
                            None           => Vec::new(),
                        };
                        uids2.extend(uids);
                        opts.uids = Some(uids2);
                    },
                    None => exit(1),
                }
            },
            Some(Ok(Opt('u', None))) => {
                eprintln!("option requires an argument -- 'u'");
                exit(1);
            },
            Some(Ok(Opt(c, _))) => {
                eprintln!("unknown option -- {:?}", c);
                exit(1);
            },
            Some(Err(err)) => {
                eprintln!("{}", err);
                exit(1);
            },
            None => break,
        }
    }
    let myself_tty_nr = match procfs::process::Process::myself() {
        Ok(process) => {
            match process.stat() {
                Ok(stat) => stat.tty_nr,
                Err(err) => {
                    eprintln!("{}", err);
                    exit(1);
                },
            }
        },
        Err(err) => {
            eprintln!("{}", err);
            exit(1);
        },
    };
    let boot_time_secs = match procfs::boot_time_secs() {
        Ok(tmp_boot_time_secs) => tmp_boot_time_secs,
        Err(err) => {
            eprintln!("{}", err);
            exit(1);
        },
    };
    let uptime = match procfs::Uptime::new() {
        Ok(tmp_uptime) => tmp_uptime.uptime,
        Err(err) => {
            eprintln!("{}", err);
            exit(1);
        },
    };
    let tick_per_sec = match procfs::ticks_per_second() {
        Ok(tmp_tick_per_sec) => tmp_tick_per_sec,
        Err(err) => {
            eprintln!("{}", err);
            exit(1);
        },
    };
    let now = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_)       => 0,
    };
    let current_tm = localtime(now as i64).unwrap();
    let mut status = 0;
    print_headers(opts.fields_and_headers.as_slice(), &opts);
    match procfs::process::all_processes() {
        Ok(processes) => {
            for process in processes {
                match process {
                    Ok(process) => {
                        let cmdline = match process.cmdline() {
                            Ok(tmp_cmdline) => Some(tmp_cmdline),
                            Err(_)          => None,
                        };
                        let stat = match process.stat() {
                            Ok(tmp_stat) => Some(tmp_stat),
                            Err(_)       => None,
                        };
                        let status = match process.status() {
                            Ok(tmp_status) => Some(tmp_status),
                            Err(_)         => None,
                        };
                        let wchan = match process.wchan() {
                            Ok(tmp_wchan) => Some(tmp_wchan),
                            Err(_)        => None,
                        };
                        if filter(&process, &stat, &status, myself_tty_nr, &opts) {
                            print_fields(opts.fields_and_headers.as_slice(), &process, &cmdline, &stat, &status, &wchan, boot_time_secs, uptime, tick_per_sec, &current_tm, &opts);
                        }
                    },
                    Err(err) => {
                        eprintln!("{}", err);
                        status = 1;
                    },
                }
            }
        },
        Err(err) => {
            eprintln!("{}", err);
            exit(1);
        },
    }
    exit(status);
}
