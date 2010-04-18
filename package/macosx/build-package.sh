#!/bin/sh

rm -f ./vpn-client-install.dmg

/usr/local/bin/freeze vpn-client-install.packproj

VOLNAME="Shrew Soft VPN Client Install"
mv build "$VOLNAME"

cp ../../LICENSE.TXT "./$VOLNAME"

/usr/bin/hdiutil create -ov -format UDRW -srcfolder "./$VOLNAME" ./vpn-client-install.dmg

mkdir ./vol

/usr/bin/hdiutil attach ./vpn-client-install.dmg -readwrite -noautoopen -mountpoint ./vol/
/bin/cp ./vpn-client-volume.icns ./vol/.VolumeIcon.icns
/Developer/Tools/SetFile -a -C ./vol

/usr/bin/hdiutil detach ./vol/
rmdir ./vol

/usr/bin/hdiutil convert ./vpn-client-install.dmg -format UDZO -o ./vpn-client-install-ro.dmg
/bin/mv -f ./vpn-client-install-ro.dmg ./vpn-client-install.dmg

rm -fr "./$VOLNAME"

