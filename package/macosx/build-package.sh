#!/bin/sh

rm -f ./vpn-client-install.dmg

VOLNAME="Shrew Soft VPN Client Install"
mkdir "./$VOLNAME"

/Developer/usr/bin/packagemaker -v -d ./vpn-client-install.pmdoc -o "./$VOLNAME/vpn-client-install.mpkg"
cp ../../LICENSE.TXT "./$VOLNAME"

/usr/bin/hdiutil create -ov -format UDRW -srcfolder "./$VOLNAME" ./vpn-client-install.dmg

mkdir ./tmp

/usr/bin/hdiutil attach ./vpn-client-install.dmg -readwrite -noautoopen -mountpoint ./tmp/
/bin/cp ./vpn-client-install.icns ./tmp/.VolumeIcon.icns
/Developer/Tools/SetFile -a -C ./tmp

/usr/bin/hdiutil detach ./tmp/
rmdir ./tmp

/usr/bin/hdiutil convert ./vpn-client-install.dmg -format UDZO -o ./vpn-client-install-ro.dmg
/bin/mv ./vpn-client-install-ro.dmg ./vpn-client-install.dmg

rm -fr "./$VOLNAME"

