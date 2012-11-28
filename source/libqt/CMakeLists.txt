#
# Shrew Soft VPN / QT Private Libs
# Cross Platform Make File
#
# author : Matthew Grooms
#        : mgrooms@shrew.net
#        : Copyright 2007, Shrew Soft Inc
#

if( APPLE )

	# QtCore Private Library Framework

	install(
		DIRECTORY "${QT_LIBRARY_DIR}/QtCore.framework/Contents"
		DESTINATION "/Library/Frameworks/ShrewSoftQtCore.framework"
		COMPONENT Runtime )

	install(
		FILES "${QT_LIBRARY_DIR}/QtCore.framework/Versions/4/QtCore"
		DESTINATION "/Library/Frameworks/ShrewSoftQtCore.framework/Versions/4"
		RENAME "ShrewSoftQtCore"
		COMPONENT Runtime )

	install(
		CODE "execute_process( COMMAND \"ln\" -s
			4
			/Library/Frameworks/ShrewSoftQtCore.framework/Versions/Current )" )

	install(
		CODE "execute_process( COMMAND \"ln\" -s
			Versions/4/Resources
			/Library/Frameworks/ShrewSoftQtCore.framework/Resources )" )

	install(
		CODE "execute_process( COMMAND \"install_name_tool\" -id
			ShrewSoftQtCore.framework/Versions/4/ShrewSoftQtCore
			/Library/Frameworks/ShrewSoftQtCore.framework/Versions/4/ShrewSoftQtCore )" )

	# QtGui Private Library Framework

	install(
		DIRECTORY "${QT_LIBRARY_DIR}/QtGui.framework/Contents"
		DESTINATION "${QT_LIBRARY_DIR}/ShrewSoftQtGui.framework"
		COMPONENT Runtime )

	install(
		FILES "${QT_LIBRARY_DIR}/QtGui.framework/Versions/4/QtGui"
		DESTINATION "/Library/Frameworks/ShrewSoftQtGui.framework/Versions/4"
		RENAME "ShrewSoftQtGui"
		COMPONENT Runtime )

	install(
		CODE "execute_process( COMMAND \"ln\" -s
			4
			/Library/Frameworks/ShrewSoftQtGui.framework/Versions/Current )" )

	install(
		CODE "execute_process( COMMAND \"ln\" -s
			Versions/4/Resources
			/Library/Frameworks/ShrewSoftQtGui.framework/Resources )" )

	install(
		DIRECTORY "${QT_LIBRARY_DIR}/QtGui.framework/Versions/4/Resources"
		DESTINATION "/Library/Frameworks/ShrewSoftQtGui.framework/Versions/4"
		COMPONENT Runtime )

	install(
		CODE "execute_process( COMMAND \"install_name_tool\" -id
			ShrewSoftQtGui.framework/Versions/4/ShrewSoftQtGui
			/Library/Frameworks/ShrewSoftQtGui.framework/Versions/4/ShrewSoftQtGui )" )

	install(
		CODE "execute_process( COMMAND \"install_name_tool\" -change
			${QT_LIBRARY_DIR}/QtCore.framework/Versions/4/QtCore
			ShrewSoftQtCore.framework/Versions/4/ShrewSoftQtCore
			/Library/Frameworks/ShrewSoftQtGui.framework/Versions/4/ShrewSoftQtGui )" )

endif( APPLE )
