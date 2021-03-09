#!/bin/sh
# ------------------------------------------------------------------------------
#  Pi.Alert
#  Open Source Network Guard / WIFI & LAN intrusion detector 
#
#  create_tar.sh - Create the tar file for installation
# ------------------------------------------------------------------------------
#  GNU GPLv3
# ------------------------------------------------------------------------------

PIALERT_VERSION=`awk '$1=="VERSION" { print $3 }' ../config/version.conf | tr -d \'`
PIALERT_DEV_PATH=/media/WD_4TB/dev

# ------------------------------------------------------------------------------
cd $PIALERT_DEV_PATH
pwd

# ------------------------------------------------------------------------------
ls -l pialert/tar/pialert*.tar
tar tvf pialert/tar/pialert_latest.tar | wc -l
rm pialert/tar/pialert_*.tar

# ------------------------------------------------------------------------------
tar cvf pialert/tar/pialert_$PIALERT_VERSION.tar --exclude="pialert/tar" --exclude="pialert/.git" pialert | wc -l

ln -s pialert_$PIALERT_VERSION.tar pialert/tar/pialert_latest.tar
ls -l pialert/tar/pialert*.tar
