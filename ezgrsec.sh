#!/bin/bash
#
#	GRSec Full Automation
#
# 	(C) Bryan Andrews (.org) 2014 GLPv2
#
#	https://github.com/BIAndrews/ezgrsec

# get the latest versions and releases from http://grsecurity.net/download.php , is it possible to automate this? YES!
DEF_GRSEC_TYPE=stable
latest_gradm=`wget -qO- http://grsecurity.net/download.php|grep stable/|sed -e's/.*href="stable//' -e's/".*//'|grep gradm`
if [ $DEF_GRSEC_TYPE == "stable" ]; then
 latest_grsec=`wget -qO- http://grsecurity.net/download.php|grep stable/|sed -e 's/\s\+/\n/g'|grep stable/|head -1|sed -e's/.*stable\///' -e's/"//'`
 DEF_GRSECV=`echo $latest_grsec|awk -F- '{print $2}'`
 DEF_GRSECRELEASE=`echo $latest_grsec|awk -F- '{print $4}'|sed -e's/\..*//'`;
 DEF_GRADMNRELEASE=`echo $latest_gradm|awk -F- '{print $3}'|sed -e's/\..*//'`;
 DEF_KERNELV=`echo $latest_grsec|awk -F- '{print $3}'`;
fi
if [ $DEF_GRSEC_TYPE == "test" ]; then
 latest_grsec=`wget -qO- http://grsecurity.net/download.php|grep test/|sed -e's/.*href="test//' -e's/".*//'|head -1`
 DEF_GRSECV=`echo $latest_grsec|awk -F- '{print $2}'`
 DEF_GRSECRELEASE=`echo $latest_grsec|awk -F- '{print $4}'|sed -e's/\..*//'`;
 DEF_GRADMNRELEASE=`echo $latest_gradm|awk -F- '{print $3}'|sed -e's/\..*//'`;
 DEF_KERNELV=`echo $latest_grsec|awk -F- '{print $3}'`;
fi
# get from https://pax.grsecurity.net/
DEF_PAXV=0.9
# defaults
DEF_RPMRELEASE=0
DEF_MAKERPMS=y
#todo: move to github repo master/raw link
TAR2RPMSRC=http://www.bryanandrews.org/files/tar2rpm
DEF_BUILDROOT=/usr/src



##########################################################################################
#
#	YOU PROBABLY DON'T NEED TO EDIT ANYTHING BELOW THIS POINT
#

GRSECKERNELCONFIG="
#
# Enable /proc/config.gz
#
CONFIG_PROC_FS=y
CONFIG_IKCONFIG=y
CONFIG_IKCONFIG_PROC=y
#
# Grsecurity - BryanAndrews.org Quick GRSec Guide
#
CONFIG_GRKERNSEC=y
# CONFIG_GRKERNSEC_LOW is not set
# CONFIG_GRKERNSEC_MEDIUM is not set
# CONFIG_GRKERNSEC_HIGH is not set
CONFIG_GRKERNSEC_CUSTOM=y
# Address Space Protection
#
# CONFIG_GRKERNSEC_KMEM is not set
# CONFIG_GRKERNSEC_IO is not set
CONFIG_GRKERNSEC_PROC_MEMMAP=y
CONFIG_GRKERNSEC_BRUTE=y
CONFIG_GRKERNSEC_MODHARDEN=y
CONFIG_GRKERNSEC_HIDESYM=y
# CONFIG_GRKERNSEC_KERN_LOCKOUT is not set

#
# Role Based Access Control Options
#
# CONFIG_GRKERNSEC_NO_RBAC is not set
CONFIG_GRKERNSEC_ACL_HIDEKERN=y
CONFIG_GRKERNSEC_ACL_MAXTRIES=3
CONFIG_GRKERNSEC_ACL_TIMEOUT=30

#
# Filesystem Protections
#
CONFIG_GRKERNSEC_PROC=y
# CONFIG_GRKERNSEC_PROC_USER is not set
CONFIG_GRKERNSEC_PROC_USERGROUP=y
CONFIG_GRKERNSEC_PROC_GID=2000
CONFIG_GRKERNSEC_PROC_ADD=y
CONFIG_GRKERNSEC_LINK=y
CONFIG_GRKERNSEC_FIFO=y
CONFIG_GRKERNSEC_SYSFS_RESTRICT=y
CONFIG_GRKERNSEC_ROFS=y
CONFIG_GRKERNSEC_CHROOT=y
CONFIG_GRKERNSEC_CHROOT_MOUNT=y
CONFIG_GRKERNSEC_CHROOT_DOUBLE=y
CONFIG_GRKERNSEC_CHROOT_PIVOT=y
CONFIG_GRKERNSEC_CHROOT_CHDIR=y
CONFIG_GRKERNSEC_CHROOT_CHMOD=y
CONFIG_GRKERNSEC_CHROOT_FCHDIR=y
CONFIG_GRKERNSEC_CHROOT_MKNOD=y
CONFIG_GRKERNSEC_CHROOT_SHMAT=y
CONFIG_GRKERNSEC_CHROOT_UNIX=y
CONFIG_GRKERNSEC_CHROOT_FINDTASK=y
CONFIG_GRKERNSEC_CHROOT_NICE=y
CONFIG_GRKERNSEC_CHROOT_SYSCTL=y
CONFIG_GRKERNSEC_CHROOT_CAPS=y


#
# Kernel Auditing
#
CONFIG_GRKERNSEC_AUDIT_GROUP=y
CONFIG_GRKERNSEC_AUDIT_GID=2005
CONFIG_GRKERNSEC_EXECLOG=y
CONFIG_GRKERNSEC_RESLOG=y
CONFIG_GRKERNSEC_CHROOT_EXECLOG=y
CONFIG_GRKERNSEC_AUDIT_PTRACE=y
# CONFIG_GRKERNSEC_AUDIT_CHDIR is not set
CONFIG_GRKERNSEC_AUDIT_MOUNT=y
CONFIG_GRKERNSEC_SIGNAL=y
CONFIG_GRKERNSEC_FORKFAIL=y
CONFIG_GRKERNSEC_TIME=y
CONFIG_GRKERNSEC_PROC_IPADDR=y
CONFIG_GRKERNSEC_RWXMAP_LOG=y
CONFIG_GRKERNSEC_AUDIT_TEXTREL=y

#
# Executable Protections
#
CONFIG_GRKERNSEC_EXECVE=y
CONFIG_GRKERNSEC_DMESG=y
CONFIG_GRKERNSEC_HARDEN_PTRACE=y
CONFIG_GRKERNSEC_TPE=y
# CONFIG_GRKERNSEC_TPE_ALL is not set
# CONFIG_GRKERNSEC_TPE_INVERT is not set
# OLD VERSION CONFIG_GRKERNSEC_TPE_GID=2001
CONFIG_GRKERNSEC_TPE_UNTRUSTED_GID=2001

#
# Network Protections
#
CONFIG_GRKERNSEC_RANDNET=y
# CONFIG_GRKERNSEC_BLACKHOLE is not set
CONFIG_GRKERNSEC_SOCKET=y
CONFIG_GRKERNSEC_SOCKET_ALL=y
CONFIG_GRKERNSEC_SOCKET_ALL_GID=2002
CONFIG_GRKERNSEC_SOCKET_CLIENT=y
CONFIG_GRKERNSEC_SOCKET_CLIENT_GID=2003
CONFIG_GRKERNSEC_SOCKET_SERVER=y
CONFIG_GRKERNSEC_SOCKET_SERVER_GID=2004

#
# Sysctl support
#
CONFIG_GRKERNSEC_SYSCTL=y
CONFIG_GRKERNSEC_SYSCTL_ON=y

#
# Logging Options
#
CONFIG_GRKERNSEC_FLOODTIME=10
CONFIG_GRKERNSEC_FLOODBURST=20

#
# PaX
#
CONFIG_TASK_SIZE_MAX_SHIFT=47
CONFIG_PAX=y

#
# PaX Control
#
# CONFIG_PAX_SOFTMODE is not set
CONFIG_PAX_EI_PAX=y
CONFIG_PAX_PT_PAX_FLAGS=y
# CONFIG_PAX_NO_ACL_FLAGS is not set
CONFIG_PAX_HAVE_ACL_FLAGS=y
# CONFIG_PAX_HOOK_ACL_FLAGS is not set

#
# Non-executable pages
#
CONFIG_PAX_NOEXEC=y
CONFIG_PAX_PAGEEXEC=y
CONFIG_PAX_EMUTRAMP=y
CONFIG_PAX_MPROTECT=y
CONFIG_PAX_MPROTECT_COMPAT=y
# CONFIG_PAX_ELFRELOCS is not set

#
# Address Space Layout Randomization
#
CONFIG_PAX_ASLR=y
CONFIG_PAX_RANDKSTACK=y
CONFIG_PAX_RANDUSTACK=y
CONFIG_PAX_RANDMMAP=y

#
# Miscellaneous hardening features
#
CONFIG_PAX_MEMORY_SANITIZE=y
# CONFIG_PAX_MEMORY_STACKLEAK is not set
CONFIG_PAX_REFCOUNT=y
# CONFIG_PAX_USERCOPY is not set
"

# old school
#yellow='\e[1;33m'
#blue='\e[1;34m'
#white='\e[1;37m'
#NC='\e[0m'

# new school
#http://stackoverflow.com/questions/5947742/how-to-change-the-output-color-of-echo-in-linux
yellow=$(tput setaf 3)
blue=$(tput setaf 4)
white=$(tput bold setaf 9)
NC=$(tput sgr0)

# default wget options
WGETOPT="-c -nv"
TEE="tee -a $LOGFILE"


echo
echo "This script is an automation tool for downloading, patching, and compiling the Linux kernel with GRSec security patches. Supplemental GRSec related tools like gradm and paxctl are included. Optional RPM packaging and RPM .SPEC creation is done. These RPM and .SPEC files are saved in the current users home directory. This is hard coded for 64bit systems only. If you later install the produced kernel RPM package you will need to create the groups specified below. These are also adjustable in the sysctl settings before the system is locked."
echo -e "
The following groups will be created for you:

${blue}Group GID ${white}2000${NC}	grs-proc	This group is for non-root users that need access to the /proc system.
${blue}Group GID ${white}2001${NC}	grs-tpe		All users in this group are only able to exec files in root owned dirs writable by root, nothing more.
${blue}Group GID ${white}2002${NC}	grs-sock-all	Group to disable all socket access.
${blue}Group GID ${white}2003${NC}	grs-sock-client	Group to disable all client only socket access.
${blue}Group GID ${white}2004${NC}	grs-sock-sever	Group to disable all server only socket access.
${blue}Group GID ${white}2005${NC}	grs-audit	Group to enforce full auditing through syslog. Logs exec, ptrace, mount, sig, and chdir. 
"


function print_Line()
{
	#for i in {1..$C}; do echo "-"; done
	for (( c=0; c<=$COLUMNS; c++ )); do
		 [ $c -ne 1 ] && echo -n "-"
	done
	echo
}

do_getAnswer()
{
	[ $4 ] && TIMEOUT="-t $4"
	read $TIMEOUT -e -p "${blue}$3${NC}: " -i "$1" ANSWER
        export ${2}="$ANSWER"

        #echo -ne "${blue}$3${NC} [$1]: "
        #read -e ANSWER

        #if [ -z $ANSWER ]; then
        #        #echo "...defaulting to $1."
        #        export ${2}="$1"
        #else
        #        export ${2}="$ANSWER"
        #fi

}

#
# Poorly named function to handle post RPM house cleaning. $2 is destination and it has to be a dir not a file, defaults to ~
do_Bee()
{
	SRC=$1
        DST=$2
        RPM=$(basename $SRC)
	if [ -f "$DST" ];then echo -n " (overwriting ${DST}/${RPM}) " | $TEE; fi
	mv -bf $SRC $DST

	if [ -f "$DST/$RPM.info" ];then echo -n " (overwriting $RPM.info) " | $TEE; fi
        rpm -qpi "$DST/$RPM" > "$DST/$RPM.info"

	if [ -f "$DST/$RPM.md5" ];then echo -n " (overwriting $RPM.md5) " | $TEE; fi
        cd "$DST"; md5sum "$DST/$RPM" > "$DST/$RPM.md5"; cd "$OLDPWD";

	if [ -f "$DST/$RPM.filelist" ];then echo -n " (overwriting $RPM.filelist) " | $TEE; fi
        rpm -qpl "$DST/$RPM" > "$DST/$RPM.filelist"

	ENDMSG="${ENDMSG}Created ${white}${DST}/${RPM}${NC}\n"
}

pOK()
{
	echo -e " ${yellow}OK${NC}"
}

# fail safe just in case
if [ ! -x `which yum` ];then
	print_Line; echo "ERROR: this is only tested on CentOS6 with yum."; print_Line;
	exit 1
fi

do_getAnswer $DEF_BUILDROOT BUILDROOT "Build root directory"
install -d $BUILDROOT # just in case
LOGFILE="$BUILDROOT/bryans_grsec-$(date +%Y%m%d%H%M).log"
do_getAnswer $DEF_GRSECV GRSECV "GRSEc version"
# this isn't even an option to change anymore, no point in it really
#do_getAnswer $DEF_GRSECCONFIG GRSECCONFIG "GRSEc kernel configs file"
GRSECCONFIG="grsec_kernel_config.cfg"
do_getAnswer $DEF_GRSECRELEASE GRSECRELEASE "GRSec Release"
do_getAnswer $DEF_GRADMNRELEASE GRADMNRELEASE "GRAdmin Release"
do_getAnswer $DEF_KERNELV KERNELV "Linux Kernel version"
do_getAnswer $DEF_PAXV PAXV "PAXctl version"
do_getAnswer $DEF_MAKERPMS MAKERPMS "Make RPMs?"
MAKERPMS=${MAKERPMS,,} #trick to convert it to all lower case

if [ "$MAKERPMS" == "y" ]; then
	do_getAnswer $DEF_RPMRELEASE RPMRELEASE "This RPM release number"
fi

PAXURL="http://pax.grsecurity.net/paxctl-$PAXV.tar.gz"
GRSECURL="http://grsecurity.net/stable/grsecurity-$GRSECV-$KERNELV-$GRSECRELEASE.patch"
GRADMNURL="http://grsecurity.net/stable/gradm-$GRSECV-$GRADMNRELEASE.tar.gz"
# since the test grsec patch is for the v4.x kernel:
if [ `echo $KERNELV|head -c1` == 3 ]; then
 KERNELURL="https://www.kernel.org/pub/linux/kernel/v3.x/linux-$KERNELV.tar.xz"
fi
if [ `echo $KERNELV|head -c1` == 4 ]; then
 KERNELURL="https://www.kernel.org/pub/linux/kernel/v4.x/linux-$KERNELV.tar.xz"
fi
KERNELTAR="`basename $KERNELURL`"
CORES=$((`cat /proc/cpuinfo | grep processor | wc -l` * 2))

###################################################################################
# Showing the user and logging all the chosen settings
#
echo
echo "BUILD ROOT=$BUILDROOT" > "$BUILDROOT/$$.txt"
[ "$MAKERPMS" == "y" ] && echo "RPM RELEASE=$RPMRELEASE" >> "$BUILDROOT/$$.txt"
echo "KERNEL Version=$KERNELV" >> "$BUILDROOT/$$.txt"
echo "GRSEC Version=$GRSECV" >> "$BUILDROOT/$$.txt"
echo "GRSEC RELEASE=$GRSECRELEASE" >> "$BUILDROOT/$$.txt"
echo "GRADMN RELEASE=$GRADMNRELEASE" >> "$BUILDROOT/$$.txt"
echo "CPU CORES=$CORES" >> "$BUILDROOT/$$.txt"
echo "LOG File=$LOGFILE" >> "$BUILDROOT/$$.txt"
echo "BOOT PATH=/boot/" >> "$BUILDROOT/$$.txt"
echo "PAX URL=$PAXURL" >> "$BUILDROOT/$$.txt"
echo "GRSEC URL=$GRSECURL" >> "$BUILDROOT/$$.txt"
echo "GRADM URL=$GRADMNURL" >> "$BUILDROOT/$$.txt"
echo "KERNEL URL=$KERNELURL" >> "$BUILDROOT/$$.txt"
echo "KERNEL TARBALL=$KERNELTAR" >> "$BUILDROOT/$$.txt"
echo "DESTINATION PACKAGE DIR=$HOME" >> "$BUILDROOT/$$.txt"
column -s "=" -t "$BUILDROOT/$$.txt" | $TEE
rm "$BUILDROOT/$$.txt"
echo
echo -n -e "This will download, install, and compile the Linux GRSec kernel on this system. If you do not want to do this press CTRL+C now to quit.\n${white}Press any key to continue...${NC} "
read $nope

# verifying the log file is fresh and exists
echo "BEGINNING OF THE RUN..." > $LOGFILE
echo `date` >> $LOGFILE


############################################################################
#
# Ensure system groups for GRSec
#
grep 2000 /etc/group >/dev/null
if [ $? -ne 0 ]; then
groupadd -g 2000 grs-proc
echo "Added group 2000 grs-proc" >> $LOGFILE
fi

grep 2001 /etc/group >/dev/null
if [ $? -ne 0 ]; then
groupadd -g 2001 grs-tpe
echo "Added group 2001 grs-tpe" >> $LOGFILE
fi

grep 2002 /etc/group >/dev/null
if [ $? -ne 0 ]; then
groupadd -g 2002 grs-sock-all
echo "Added group 2002 grs-sock-all" >> $LOGFILE
fi

grep 2003 /etc/group >/dev/null
if [ $? -ne 0 ]; then
groupadd -g 2003 grs-sock-client
echo "Added group 2003 grs-sock-client" >> $LOGFILE
fi

grep 2004 /etc/group >/dev/null
if [ $? -ne 0 ]; then
groupadd -g 2004 grs-sock-server
echo "Added group 2004 grs-sock-server" >> $LOGFILE
fi

grep 2005 /etc/group >/dev/null
if [ $? -ne 0 ]; then
groupadd -g 2005 grs-audit
echo "Added group 2005 grs-audit" >> $LOGFILE
fi


if [ -d ${BUILDROOT}/linux ];then
print_Line
echo -e "Detected ${BUILDROOT}/linux, this directory will be overwritten. If you do not want to do this press CTRL+C now to quit. \n${white}Automatically continuing in 5 seconds...${NC} " | $TEE
# 5 second timeout, not safe but in for debugging
read -t 5 $nope
fi


#####################################################################################
#
#	Packages required to build a kernel on this box.
#
echo -n "Installing prereq tools to build the kernel..." | $TEE

	yum -y install xz patch wget grubby >> $LOGFILE
	if [ $? -ne 0 ];then print_Line; echo "Fatal error installing/verifying packages: xz patch wget grubby."; print_Line; exit 1; fi

	yum -y groupinstall "Development Tools" >> $LOGFILE 2>&1
	if [ $? -ne 0 ];then print_Line; echo "Fatal error installing/verifying package group: \"Development Tools\"."; print_Line; exit 1; fi

pOK


#################################################################
#
# Build pax util...
#

cd ${BUILDROOT}
if [ ! -f `basename $PAXURL` ]; then wget $WGETOPT "$PAXURL" >> $LOGFILE 2>&1; fi

if [ "$MAKERPMS" == "y" ]; then

	echo -n "Building paxctl RPM..."
	cd ${BUILDROOT}

cat >paxctl.spec <<EOL
Summary:        paxctl
Name:           paxctl
Version:        ${PAXV}
Release:        ${RPMRELEASE}
License:        GPL
Source0:        paxctl-%{version}.tar.gz
URL:            http://www.BryanAndrews.org
BuildArch:      x86_64
BuildRoot:      %{_tmppath}/%{name}-build
Group:          Applications/System
Vendor:         https://pax.grsecurity.net
Packager:       GRSec Full Automation by Bryan Andrews http://www.BryanAndrews.org

%define debug_package %{nil}

%description
This package provides paxctl for use with GRSec kernels. https://grsecurity.net/

%prep

%setup -q

%build
make

#%%configure

%install
%{__make} install DESTDIR=%{buildroot}

%files
%defattr(-,root,root)
/sbin/paxctl
/usr/share/man/man1/paxctl.1.gz
EOL

	install -d /root/rpmbuild/SOURCES/
	cp ${BUILDROOT}/paxctl-$PAXV.tar.gz /root/rpmbuild/SOURCES/

	if [ -f /root/.rpmmacros ]; then mv -f /root/.rpmmacros /root/.rpmmacros~; fi
	rpmbuild -bb paxctl.spec >> $LOGFILE 2>&1
	if [ $? -eq 0 ];then

	        do_Bee "/root/rpmbuild/RPMS/x86_64/paxctl-$PAXV-${RPMRELEASE}.x86_64.rpm" $HOME
		pOK

		if [ -f "/root/rpmbuild/SOURCES/paxctl-$PAXV.tar.gz" ];then
			# house cleaning
			rm "/root/rpmbuild/SOURCES/paxctl-$PAXV.tar.gz"
			rm paxctl.spec
		fi
	else
		echo
		echo "Fatal error: failed to build paxctl RPM. See log at $LOGFILE"
	fi

fi

echo -n "Installing PAX..."

cd ${BUILDROOT}
tar xfz `basename $PAXURL` >> $LOGFILE
cd paxctl-$PAXV
make >> $LOGFILE 2>&1
if [ $? -ne 0 ];then echo "Fatal error compiling paxctl." | $TEE; exit 1; fi
make install >> $LOGFILE 2>&1
if [ $? -ne 0 ];then echo "Fatal error installing paxctl." | $TEE; exit 1; fi

pOK




############################################################
#
# Build gradm RPM
#

cd ${BUILDROOT}
if [ ! -f `basename $GRADMNURL` ]; then wget $WGETOPT "$GRADMNURL" >> $LOGFILE 2>&1; fi

if [ "$MAKERPMS" == "y" ]; then

	echo -n "Building gradm RPM..." | $TEE
	cd ${BUILDROOT}

cat >gradm.spec <<EOL
Summary:        gradm
Name:           gradm
Version:        ${GRSECV}
Release:        ${RPMRELEASE}
License:        GPLv2
Source0:        %{name}-%{version}-${GRADMNRELEASE}.tar.gz
URL:            http://www.BryanAndrews.org
BuildArch:      x86_64
BuildRoot:      %{_tmppath}/%{name}-build
Group:          Applications/System
Vendor:         https://grsecurity.net
Packager:       GRSec Full Automation by Bryan Andrews http://www.BryanAndrews.org

%define debug_package %{nil}

%description
This package provides gradm for use with GRSec kernels. https://grsecurity.net/

%prep

%setup -q -n %{name}

%build
make

#%%configure

%install
%{__make} install DESTDIR=%{buildroot}

%post
[ ! -c /dev/grsec ] && mknod -m 0622 /dev/grsec c 1 13

%files
%defattr(-,root,root)
/usr/share/man/man8/gradm.8.gz
/etc/grsec/policy
/etc/grsec/learn_config
/sbin/grlearn
/sbin/gradm
EOL

	install -d /root/rpmbuild/SOURCES/
	cp ${BUILDROOT}/gradm-$GRSECV-$GRADMNRELEASE.tar.gz /root/rpmbuild/SOURCES/

	if [ -f /root/.rpmmacros ]; then mv -f /root/.rpmmacros /root/.rpmmacros~; fi
	rpmbuild -bb gradm.spec >> $LOGFILE 2>&1
	if [ $? -eq 0 ];then

		do_Bee "/root/rpmbuild/RPMS/x86_64/gradm-$GRSECV-${RPMRELEASE}.x86_64.rpm" $HOME
		pOK

		if [ -f "/root/rpmbuild/SOURCES/gradm-$GRSECV-$GRADMNRELEASE.tar.gz" ];then
			# house cleaning
			rm "/root/rpmbuild/SOURCES/gradm-$GRSECV-$GRADMNRELEASE.tar.gz"
			rm gradm.spec
		fi
	else
		echo
		echo "Fatal error: failed to build gradm RPM. See log at $LOGFILE"
	fi


fi

echo -n "Building gradm..."

cd ${BUILDROOT}
tar zxf gradm-$GRSECV-$GRADMNRELEASE.tar.gz >> $LOGFILE
if [ $? -ne 0 ];then echo "Fatal error exploding gradm tar." | $TEE; exit 1; fi
cd gradm
make -j$CORES >> $LOGFILE 2>&1
if [ $? -ne 0 ];then echo "Fatal error compiling gradm." | $TEE; exit 1; fi

if [ ! -f /etc/grsec/pw ];then
	# this is to prevent gradm from hanging forever on automated installs, this password needs to be set by the end user
	install -d /etc/grsec
	touch /etc/grsec/pw
fi
make install >> $LOGFILE 2>&1
# gradm install is different. It will install but exit with errorlevel != 0 because the current kernel isn't grsec, which often it isn't. so we pretend.

pOK


#####################################################################################
#
#	Download, patch, compile, install the kernel
#
echo -n "Downloading kernel $KERNELV and GRSec patch $GRSECV..." | $TEE
	cd ${BUILDROOT}
	if [ ! -f `basename $KERNELURL` ]; then wget $WGETOPT "$KERNELURL" >> $LOGFILE 2>&1; fi
	#if [ -d linux-$KERNELV ];then mv -f linux-$KERNELV linux-$KERNELV-$(date +%F:%R); echo "Backed up existing kernel source to ${BUILDROOT}/linux-$KERNELV-$(date +%F:%R)" >> $LOGFILE; fi

	if [ ! -d "linux-$KERNELV" ];then
		tar xfJ $KERNELTAR >> $LOGFILE
	fi

	#if [ -h "linux" ];then
		rm -rf linux
		ln -sf linux-$KERNELV linux
	#else
	#	echo "${BUILDROOT}/linux not a sym link. Not deleting it"
	#	exit 1
	#fi

	if [ ! -f `basename $GRSECURL` ]; then
		wget $WGETOPT "$GRSECURL" >> $LOGFILE 2>&1
		if [ $? -ne 0 ];then print_Line; echo "Fatal error downloading $GRSECURL" | $TEE; print_Line; exit 1; fi
	fi

	if [ ! -f "grsecurity-$GRSECV-$KERNELV-$GRSECRELEASE.patch" ]; then
		echo
		echo "Fatal error: unable to find grsecurity-$GRSECV-$KERNELV-$GRSECRELEASE.patch" | $TEE
		exit 1
	fi

	if [ ! -f "linux/grsecurity-$GRSECV-$KERNELV-$GRSECRELEASE.patch" ]; then
		cp "grsecurity-$GRSECV-$KERNELV-$GRSECRELEASE.patch" linux/
		cd linux
		patch -p1 < "grsecurity-$GRSECV-$KERNELV-$GRSECRELEASE.patch" >> $LOGFILE
		cd ..
	fi


	cd ${BUILDROOT}/linux
	if [ ! -f ".config" ];then
		if [ -f "/boot/config-`uname -r`" ];then
			cat /boot/config-`uname -r` > .config
		else
			if [ -f /proc/config.gz ];then
				zcat /proc/config.gz > .config
			fi
		fi
	fi

	cd ${BUILDROOT}/linux
	if [ ! -f ".config" ];then
		echo
		echo -e "${white}Fatal error:${NC} unable to create .config from current kernel. I looked in /boot/config-`uname -r` and for /proc/config.gz then gave up. Sorry things did not work out." | $TEE
		exit 1
	fi
pOK

##############################################################
# GRsec configs and make old
#
cd "${BUILDROOT}/linux"
if [ ! -f $GRSECCONFIG ];then
	# grsec kernel config file doesn't exist so lets create it with defaults
	echo -n "Creating GRSec kernel configs in $GRSECCONFIG with defaults" | $TEE
cat > $GRSECCONFIG << EOL
${GRSECKERNELCONFIG}
EOL
  	pOK
else
	echo -n "Using GRSec kernel config already found in $GRSECCONFIG" | $TEE
	pOK
fi


	# just for the record
	echo "USING GRSEC KERNEL CONFIG SETTINGS:" >> $LOGFILE
	cat $GRSECCONFIG >> $LOGFILE
	echo "" >> $LOGFILE

	# copy the grsec kernel configs into the .config we will use to compile this kernel
	cat $GRSECCONFIG >> .config


echo -n "Using live kernel config to create a compatible new GRSec $GRSECV config..." | $TEE
	yes "" | make oldconfig >> $LOGFILE 2>&1
pOK




##############################################################
#
# kernel compile
#

cd ${BUILDROOT}/linux
if [ -f "arch/x86_64/boot/bzImage" ];then
	echo -n "Existing kernel binary found, using that. Run make clean in $BUILDROOT to have this script recompile the kernel." | $TEE
	pOK
else
	echo -n "Compiling the kernel with $CORES threads..." | $TEE
		make -j$CORES bzImage >> $LOGFILE 2>&1
		if [ $? -ne 0 ];then print_Line; echo "Fatal error compiling kernel binary image." | $TEE; print_Line; exit 1; fi
	pOK

	echo -n "Installing new kernel at /boot/vmlinuz-$KERNELV-grsec ..." | $TEE
		make install >> $LOGFILE 2>&1
	pOK
fi

##############################################################
#
# kernel modules compile and install
#

if [ -f "/lib/modules/$KERNELV-grsec/modules.dep" ];then

	echo -n "Modules for $KERNELV-grsec already installed. To force a recompile and reinstall delete /lib/modules/$KERNELV-grsec" | $TEE
	pOK

else

	echo -n "Compiling modules..." | $TEE
	make -j$CORES modules >> $LOGFILE 2>&1
	if [ $? -ne 0 ];then print_Line; echo "Fatal error compiling kernel modules." | $TEE; print_Line; exit 1; fi
	pOK

	echo -n "Installing modules..." | $TEE
	make modules_install install >> $LOGFILE 2>&1
	pOK
	fi

##############################################################
#
# Install kernel
#
echo >> $LOGFILE
#grubby --info /boot/vmlinuz-$KERNELV-grsec >> $LOGFILE 2>&1
#if [ $? -eq 1 ];then

	echo -n "Installing the new kernel with grubby..." | $TEE

	# this is needed when we run this script over and over on the same box for release fixes
	if [ -f /boot/vmlinuz-$KERNELV-grsec.old ];then rm /boot/vmlinuz-$KERNELV-grsec.old; fi
	if [ -f /boot/System.map-$KERNELV-grsec.old ];then rm /boot/System.map-$KERNELV-grsec.old; fi
	cp .config /boot/config-$KERNELV-grsec
	# selinux needs to be off on boot

	grubby --update-kernel=/boot/vmlinuz-$KERNELV-grsec --args=selinux=0 >> $LOGFILE
	if [ $? -ne 0 ];then
		#something bad happened
		echo "Fatal error: unable to install kernel /boot/vmlinuz-$KERNELV-grsec" | $TEE
		exit 1
	fi
	pOK

	if [ "$MAKERPMS" == "y" ]; then

	        ##tar for rpm build
	        if [ ! -x "${BUILDROOT}/tar2rpm" ]; then
			echo "Downloading and installing tar2rpm into ${BUILDROOT}"
		        wget -q -O ${BUILDROOT}/tar2rpm "$TAR2RPMSRC"
	        	chmod a+x ${BUILDROOT}/tar2rpm
	        fi

	        if [ ! -x "${BUILDROOT}/tar2rpm" ]; then
			echo "Failed to get tar2rpm tool. Can not continue"
			exit 1
		fi

		# the kernel must already be installed before we do this
		cd ${BUILDROOT}
		echo -n "Tarballing ${BUILDROOT}/linux-$KERNELV-grsec-$GRSECV.tar for RPM conversion..." | $TEE
		tar cf ${BUILDROOT}/linux-$KERNELV-grsec-$GRSECV.tar /boot/*-$KERNELV-grsec* /lib/modules/$KERNELV-grsec > /dev/null 2>&1
		pOK

	        ## install kernel script
	        echo "grubby --copy-default --make-default --title=\"Kernel $KERNELV-grsec\" --args=selinux=0 --initrd=/boot/initramfs-$KERNELV-grsec.img --add-kernel=/boot/vmlinuz-$KERNELV-grsec" > kernel-grsec-install.sh

	        ## uninstall kernel script
	        echo "grubby --remove-kernel=/boot/vmlinuz-$KERNELV-grsec" > kernel-grsec-uninstall.sh

	        ## make an rpm
		echo -n "Converting to an RPM..." | $TEE
		${BUILDROOT}/tar2rpm -t / -a x86_64 -r "$RPMRELEASE" --name "kernel-grsec" -v "$KERNELV.$GRSECV" -rq "gradm,grsec-paxctl" -po kernel-grsec-install.sh -poun kernel-grsec-uninstall.sh ${BUILDROOT}/linux-$KERNELV-grsec-$GRSECV.tar | $TEE
		pOK

		echo -n "Checking for Kernel RPM..." | $TEE
	        if [ -f "/tmp/kernel-grsec-$KERNELV.$GRSECV-$RPMRELEASE/RPMS/x86_64/kernel-grsec-$KERNELV.$GRSECV-$RPMRELEASE.x86_64.rpm" ];then
		        do_Bee /tmp/kernel-grsec-$KERNELV.$GRSECV-$RPMRELEASE/RPMS/x86_64/kernel-grsec-$KERNELV.$GRSECV-$RPMRELEASE.x86_64.rpm $HOME
			pOK
		        rm ${BUILDROOT}/linux-$KERNELV-grsec-$GRSECV.tar kernel-grsec-install.sh kernel-grsec-uninstall.sh
			rm -rf /tmp/kernel-grsec-$KERNELV.$GRSECV-$RPMRELEASE
			# todo: BUILDROOT cleanup from rpmbuild
		else
			echo "Fatal error creating kernel RPM"
			exit 1
	        fi

	fi

#else

#	echo -n "Kernel already installed at /boot/vmlinuz-$KERNELV-grsec."
#	pOK

#fi




print_Line | $TEE
echo
echo "RUN COMPLETED SUCCESSFULLY" | $TEE
echo
echo -e $ENDMSG | $TEE
print_Line | $TEE

# lets be a good boy and exit nice
exit 0
