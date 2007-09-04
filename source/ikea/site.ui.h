/****************************************************************************
** ui.h extension file, included from the uic-generated form implementation.
**
** If you want to add, delete, or rename functions or slots, use
** Qt Designer to update this file, preserving your code.
**
** You should not define a constructor or destructor in this file.
** Instead, write your code in functions called init() and destroy().
** These will automatically be called by the form's constructor and
** destructor.
*****************************************************************************/

#include "ikea.h"

#define IDTXT_ASN1	"ASN.1 Distinguished Name"
#define IDTXT_FQDN	"Fully Qualified Domain Name"
#define IDTXT_UFQDN	"User Fully Qualified Domain Name"
#define IDTXT_ADDR	"IP Address"
#define IDTXT_KEYID	"Key Identifier"

bool combobox_setbytext( const char * text, QComboBox * cbox )
{
	long index = 0;
	long count = cbox->count();

	for( ; index < count; index++ )
	{
		if( !strcmp( text, cbox->text( index ).ascii() ) )
		{
			cbox->setCurrentItem( index );
			return true;
		}
	}

	return false;
}

void site::AddPolicy()
{
	topology t( this );
	if( t.exec() == QDialog::Accepted )
	{
		// address and netmask

		QString Address = t.lineEditAddress->text();
		Address = Address.replace( ' ', "" );

		QString Netmask = t.lineEditNetmask->text();
		Netmask = Netmask.replace( ' ', "" );

		QString n = Address + " / " + Netmask;

		// create item

		QListViewItem * i = new QListViewItem( listViewPolicies, "", n );

		// set icon

		if( !t.comboBoxType->currentItem() )
		{
			// include

			i->setPixmap( 0, QPixmap::fromMimeSource( "policy_inc.png" ) );
		}
		else
		{
			// exclude

			i->setPixmap( 0, QPixmap::fromMimeSource( "policy_exc.png" ) );
		}	
	}
}

void site::init()
{
	lineEditAddress->setInputMask( "00D . 00D . 00D . 00D" );
	lineEditAddress->setText( "0.0.0.0" );

	lineEditNetmask->setInputMask( "00D . 00D . 00D . 00D" );
	lineEditNetmask->setText( "255.255.255.255" );

	lineEditDNSServer->setInputMask( "00D . 00D . 00D . 00D" );
	lineEditDNSServer->setText( "0.0.0.0" );

#ifdef OPT_NATT

	textLabelNATTMode->setEnabled( true );
	comboBoxNATTMode->setEnabled( true );

	textLabelNATTPort->setEnabled( true );
	lineEditNATTPort->setEnabled( true );

	textLabelNATTRate->setEnabled( true );
	lineEditNATTRate->setEnabled( true );
	textLabelNATTSecs->setEnabled( true );

	combobox_setbytext( "enable", comboBoxNATTMode );

#endif

	// update dialog

	Update();
	UpdateAuth();
	UpdateExchange();
	UpdateCipher();
	UpdateTransform();
}

void site::ModPolicy()
{
	QListViewItem * i = listViewPolicies->selectedItem();
	if( i != NULL )
	{
		QString n = i->text( 1 );

		QString address = n.section( '/', 0, 0 );
		QString netmask = n.section( '/', 1, 1 );

		address = address.stripWhiteSpace();
		netmask = netmask.stripWhiteSpace();

		topology t( this );

		t.lineEditAddress->setText( address );
		t.lineEditNetmask->setText( netmask );

		if( i->pixmap( 0 )->serialNumber() ==
		    QPixmap::fromMimeSource( "policy_exc.png" ).serialNumber() )
			t.comboBoxType->setCurrentItem( 1 );

		if( t.exec() == QDialog::Accepted )
		{
			// address and netmask

			QString n;
			n = t.lineEditAddress->text();
			n += " / ";
			n += t.lineEditNetmask->text();

			i->setText( 1, n );

			// set icon

			if( !t.comboBoxType->currentItem() )
			{
				// include

				i->setPixmap( 0, QPixmap::fromMimeSource( "policy_inc.png" ) );
			}
			else
			{
				// exclude

				i->setPixmap( 0, QPixmap::fromMimeSource( "policy_exc.png" ) );
			}	
		}
	}
}

void site::DelPolicy()
{
	QListViewItem * i = listViewPolicies->selectedItem();
	if( i != NULL )
		delete i;
}

bool site::Load( CONFIG & config )
{
	char text[ MAX_CONFSTRING ];
	long numb;

	// remote name or address

	if( config.get_string( "network-host",
		text, MAX_CONFSTRING, 0 ) )
		lineEditHost->setText( text );

	// remote ike port ( default 500 )

	if( config.get_number( "network-ike-port", &numb ) )
		lineEditPort->setText( QString::number( numb, 10 ) );

	// remote config method ( default pull )

	if( config.get_string( "client-auto-mode",
		text, MAX_CONFSTRING, 0 ) )
		if( !strcmp( text, "push" ) )
			comboBoxConfigMethod->setCurrentItem( 1 );

	// local adapter mode ( default virtual )

	if( config.get_string( "client-iface",
		text, MAX_CONFSTRING, 0 ) )
		if( !strcmp( text, "direct" ) )
			comboBoxAddressMethod->setCurrentItem( 1 );

	if( !comboBoxAddressMethod->currentItem() )
	{
		// virtual adapter address

		numb = 0;
		config.get_number( "client-addr-auto", &numb );

		if( numb )
		{
			// automatic

			checkBoxAddressAuto->setChecked( true );
		}
		else
		{
			// manual

			checkBoxAddressAuto->setChecked( false );

			// adapter address

			if( config.get_string( "client-ip-addr",
				text, MAX_CONFSTRING, 0 ) )
				lineEditAddress->setText( text );

			// adapter netmask

			if( config.get_string( "client-ip-mask",
				text, MAX_CONFSTRING, 0 ) )
				lineEditNetmask->setText( text );
		}
	}

#ifdef OPT_NATT

	// nat traversal mode ( default enabled )

	if( config.get_string( "network-natt-mode",
		text, MAX_CONFSTRING, 0 ) )
		combobox_setbytext( text, comboBoxNATTMode );

	// natt not disabled

	if( comboBoxNATTMode->currentItem() )
	{
		// nat traversal port ( default 4500 )

		if( config.get_number( "network-natt-port", &numb ) )
			lineEditNATTPort->setText( QString::number( numb, 10 ) );

		// nat traversal keep alive rate ( default 30 )

		if( config.get_number( "network-natt-rate", &numb ) )
			lineEditNATTRate->setText( QString::number( numb, 10 ) );
	}

#endif

	// ike fragment mode ( default enabled )

	if( config.get_string( "network-frag-mode",
		text, MAX_CONFSTRING, 0 ) )
		combobox_setbytext( text, comboBoxFragMode );

	// ike frag not disabled

	if( comboBoxFragMode->currentItem() )
	{
		// max packet size

		if( config.get_number( "network-frag-size", &numb ) )
			lineEditFragSize->setText( QString::number( numb, 10 ) );
	}

	// dead peer detection enabled ( default enabled )

	numb = 1;
	config.get_number( "network-dpd-enable", &numb );
	if( numb )
		checkBoxDPD->setChecked( true );
	else
		checkBoxDPD->setChecked( false );

	// isakmp failure notifications enabled ( default enabled )

	numb = 1;
	config.get_number( "network-notify-enable", &numb );
	if( numb )
		checkBoxNotify->setChecked( true );
	else
		checkBoxNotify->setChecked( false );

	// login banner enabled ( default enabled )

	numb = 1;
	config.get_number( "network-banner-enable", &numb );
	if( numb )
		checkBoxBanner->setChecked( true );
	else
		checkBoxBanner->setChecked( false );

	// dns enabled ( default enabled )

	numb = 1;
	config.get_number( "client-dns-enable", &numb );

	if( !numb )
	{
		// disabled

		checkBoxDNSEnable->setChecked( false );
	}
	else
	{
		// enabled

		checkBoxDNSEnable->setChecked( true );

		// dns settings ( default automatic )

		numb = 1;
		config.get_number( "client-dns-auto", &numb );

		if( numb )
		{
			// automatic

			checkBoxDNSAuto->setChecked( true );
		}
		else
		{
			// manual

			checkBoxDNSAuto->setChecked( false );

			// dns server address

			if( config.get_string( "client-dns-addr",
				text, MAX_CONFSTRING, 0 ) )
				lineEditDNSServer->setText( text );

			// adapter netmask

			if( config.get_string( "client-dns-suffix",
				text, MAX_CONFSTRING, 0 ) )
				lineEditDNSSuffix->setText( text );
		}
	}

	// phase1 exchange type ( default main )

	if( config.get_string( "phase1-exchange",
		text, MAX_CONFSTRING, 0 ) )
	{
		if( !strcmp( text, "main" ) )
			comboBoxP1Exchange->setCurrentItem( 0 );

		if( !strcmp( text, "aggressive" ) )
			comboBoxP1Exchange->setCurrentItem( 1 );
	}

	// authentication mode ( default hybrid rsa xauth )

	if( config.get_string( "auth-method",
		text, MAX_CONFSTRING, 0 ) )
	{
		if( !strcmp( "hybrid-rsa-xauth", text ) )
			comboBoxAuthMethod->setCurrentItem( 0 );

		if( !strcmp( "mutual-rsa-xauth", text ) )
			comboBoxAuthMethod->setCurrentItem( 1 );

		if( !strcmp( "mutual-psk-xauth", text ) )
			comboBoxAuthMethod->setCurrentItem( 2 );

		if( !strcmp( "mutual-rsa", text ) )
			comboBoxAuthMethod->setCurrentItem( 3 );

		if( !strcmp( "mutual-psk", text ) )
			comboBoxAuthMethod->setCurrentItem( 4 );
	}

	UpdateAuth();

	// local identity type
	//
	// NOTE : Requires phase1 exchange type & authentication mode

	if( config.get_string( "ident-client-type",
		text, MAX_CONFSTRING, 0 ) )
	{
		if( !strcmp( "asn1dn", text ) )
			combobox_setbytext( IDTXT_ASN1, comboBoxLocalIDType );

		if( !strcmp( "fqdn", text ) )
			combobox_setbytext( IDTXT_FQDN, comboBoxLocalIDType );

		if( !strcmp( "ufqdn", text ) )
			combobox_setbytext( IDTXT_UFQDN, comboBoxLocalIDType );

		if( !strcmp( "address", text ) )
			combobox_setbytext( IDTXT_ADDR, comboBoxLocalIDType );

		if( !strcmp( "keyid", text ) )
			combobox_setbytext( IDTXT_KEYID, comboBoxLocalIDType );
	}

	// local identity data

	if( config.get_string( "ident-client-data",
		text, MAX_CONFSTRING, 0 ) )
	{
		lineEditLocalIDData->setText( text );
		checkBoxLocalIDOption->setChecked( false );
	}

	// remote identity type

	if( config.get_string( "ident-server-type",
		text, MAX_CONFSTRING, 0 ) )
	{
		if( !strcmp( "asn1dn", text ) )
			combobox_setbytext( IDTXT_ASN1, comboBoxRemoteIDType );

		if( !strcmp( "fqdn", text ) )
			combobox_setbytext( IDTXT_FQDN, comboBoxRemoteIDType );

		if( !strcmp( "ufqdn", text ) )
			combobox_setbytext( IDTXT_UFQDN, comboBoxRemoteIDType );

		if( !strcmp( "address", text ) )
			combobox_setbytext( IDTXT_ADDR, comboBoxRemoteIDType );

		if( !strcmp( "keyid", text ) )
			combobox_setbytext( IDTXT_KEYID, comboBoxRemoteIDType );
	}

	// remote identity data

	if( config.get_string( "ident-server-data",
		text, MAX_CONFSTRING, 0 ) )
	{
		lineEditRemoteIDData->setText( text );
		checkBoxRemoteIDOption->setChecked( false );
	}

	// credentials

	if( config.get_string( "auth-server-cert",
		text, MAX_CONFSTRING, 0 ) )
		lineEditCAFile->setText( text );

	if( config.get_string( "auth-client-cert",
		text, MAX_CONFSTRING, 0 ) )
		lineEditCertFile->setText( text );

	if( config.get_string( "auth-client-key",
		text, MAX_CONFSTRING, 0 ) )
		lineEditPKeyFile->setText( text );

	if( config.get_string( "auth-mutual-psk",
		text, MAX_CONFSTRING, 0 ) )
		lineEditPSK->setText( text );

	// phase1 dh group ( default auto )

	numb = 0;
	config.get_number( "phase1-dhgroup", &numb );
	switch( numb )
	{
		case 1: // group 1
			comboBoxP1DHGroup->setCurrentItem( 1 );
			break;

		case 2: // group 2
			comboBoxP1DHGroup->setCurrentItem( 2 );
			break;

		case 5: // group 5
			comboBoxP1DHGroup->setCurrentItem( 3 );
			break;

		case 14: // group 14
			comboBoxP1DHGroup->setCurrentItem( 4 );
			break;

		case 15: // group 15
			comboBoxP1DHGroup->setCurrentItem( 5 );
			break;
	}

	// phase1 cipher algorithm ( default auto )

	if( config.get_string( "phase1-cipher",
		text, MAX_CONFSTRING, 0 ) )
		combobox_setbytext( text, comboBoxP1Cipher );

	// phase1 cipher key length ( default auto )

	if( config.get_number( "phase1-keylen", &numb ) )
	{
		snprintf( text, 5, "%lu", numb );
		combobox_setbytext( text, comboBoxP1Keylen );
	}

	// phase1 hash algorithm ( default auto )

	if( config.get_string( "phase1-hash",
		text, MAX_CONFSTRING, 0 ) )
		combobox_setbytext( text, comboBoxP1Hash );

	// phase1 key life time ( default 86400 )

	if( config.get_number( "phase1-life-secs", &numb ) )
		lineEditP1LifeTime->setText( QString::number( numb, 10 ) );

	// phase1 key life data ( default 3600 )

	if( config.get_number( "phase1-life-kbytes", &numb ) )
		lineEditP1LifeData->setText( QString::number( numb, 10 ) );

	// phase2 trasform algorithm ( default auto )

	if( config.get_string( "phase2-transform",
		text, MAX_CONFSTRING, 0 ) )
		combobox_setbytext( text, comboBoxP2Transform );

	// phase2 transform key length ( default auto )

	if( config.get_number( "phase2-keylen", &numb ) )
	{
		snprintf( text, 5, "%lu", numb );
		combobox_setbytext( text, comboBoxP2Keylen );
	}

	// phase2 hmac algorithm ( default auto )

	if( config.get_string( "phase2-hmac",
		text, MAX_CONFSTRING, 0 ) )
		combobox_setbytext( text, comboBoxP2HMAC );

	// phase2 pfs group ( default disabled )

	numb = -1;
	config.get_number( "phase2-pfsgroup", &numb );

	switch( numb )
	{
		case -1: // disabled
			comboBoxP2PFSGroup->setCurrentItem( 0 );
			break;

		case 0: // automatic
			comboBoxP2PFSGroup->setCurrentItem( 1 );
			break;

		case 1:	// group 1
			comboBoxP2PFSGroup->setCurrentItem( 2 );
			break;

		case 2:	// group 2
			comboBoxP2PFSGroup->setCurrentItem( 3 );
			break;

		case 5:	// group 5
			comboBoxP2PFSGroup->setCurrentItem( 4 );
			break;

		case 14: // group 14
			comboBoxP2PFSGroup->setCurrentItem( 5 );
			break;

		case 15: // group 15
			comboBoxP2PFSGroup->setCurrentItem( 6 );
			break;
	}

	// ipcomp transform algorithm

	if( config.get_string( "ipcomp-transform",
		text, MAX_CONFSTRING, 0 ) )
		combobox_setbytext( text, comboBoxP2Compress );

	// phase2 key life time

	if( config.get_number( "phase2-life-secs", &numb ) )
		lineEditP2LifeTime->setText( QString::number( numb, 10 ) );

	// phase2 key life data

	if( config.get_number( "phase2-life-kbytes", &numb ) )
		lineEditP2LifeData->setText( QString::number( numb, 10 ) );

	// policy configuration ( default auto )

	numb = 1;
	config.get_number( "policy-list-auto", &numb );

	if( !numb )
	{
		// manual

		checkBoxPolicyAuto->setChecked( false );

		// topology exclude list

		long index = 0;

		while( config.get_string( "policy-list-exclude",
			text, MAX_CONFSTRING, index++ ) )
		{
			QListViewItem * i = new QListViewItem( listViewPolicies, "", text );
			i->setPixmap( 0, QPixmap::fromMimeSource( "policy_exc.png" ) );
		}

		// topology include list

		index = 0;

		while( config.get_string( "policy-list-include",
			text, MAX_CONFSTRING, index++ ) )
		{
			QListViewItem * i = new QListViewItem( listViewPolicies, "", text );
			i->setPixmap( 0, QPixmap::fromMimeSource( "policy_inc.png" ) );
		}
	}

	// update dialog

	Update();
	UpdateExchange();
	UpdateCipher();
	UpdateTransform();

	return true;
}

bool site::Save( CONFIG & config )
{
	// remote name or address

	config.set_string( "network-host",
		( char * ) lineEditHost->text().ascii(),
		lineEditHost->text().length() );

	// remote ike port

	config.set_number( "network-ike-port",
		lineEditPort->text().toLong() );

	// remote config method

	config.set_string( "client-auto-mode",
		( char * ) comboBoxConfigMethod->currentText().ascii(),
		comboBoxConfigMethod->currentText().length() );

	// local adapter mode

	if( comboBoxAddressMethod->currentItem() )
	{
		// direct mode

		config.set_string( "client-iface",
			"direct",
			strlen( "direct" ) );
	}
	else
	{
		// virtual mode

		config.set_string( "client-iface",
			"virtual",
			strlen( "virtual" ) );

		// adapter address

		if( checkBoxAddressAuto->isChecked() )
		{
			// automatic

			config.set_number( "client-addr-auto", 1 );
		}
		else
		{
			// manual

			config.set_number( "client-addr-auto", 0 );

			// adapter address

			QString Address = lineEditAddress->text();
			Address = Address.replace( ' ', "" );

			config.set_string( "client-ip-addr",
				( char * ) Address.ascii(),
				Address.length() );

			// adapter netmask

			QString Netmask = lineEditNetmask->text();
			Netmask = Netmask.replace( ' ', "" );

			config.set_string( "client-ip-mask",
				( char * ) Netmask.ascii(),
				Netmask.length() );
		}
	}

#ifdef OPT_NATT

	// nat traversal mode

	config.set_string( "network-natt-mode",
		( char * ) comboBoxNATTMode->currentText().ascii(),
		comboBoxNATTMode->currentText().length() );

	// natt not disabled

	if( comboBoxNATTMode->currentItem() )
	{
		// nat traversal port

		config.set_number( "network-natt-port",
			lineEditNATTPort->text().toLong() );

		// nat traversal keep alive rate

		config.set_number( "network-natt-rate",
			lineEditNATTRate->text().toLong() );
	}

#endif

	// ike fragment mode

	config.set_string( "network-frag-mode",
		( char * ) comboBoxFragMode->currentText().ascii(),
		comboBoxFragMode->currentText().length() );

	// ike frag not disabled

	if( comboBoxFragMode->currentItem() )
	{
		// max packet size

		config.set_number( "network-frag-size",
			lineEditFragSize->text().toLong() );
	}

	// dead peer detection enabled

	if( !checkBoxDPD->isChecked() )
		config.set_number( "network-dpd-enable", 0 );
	else
		config.set_number( "network-dpd-enable", 1 );

	// isakmp failure notifications enabled

	if( !checkBoxNotify->isChecked() )
		config.set_number( "network-notify-enable", 0 );
	else
		config.set_number( "network-notify-enable", 1 );

	// login banner enabled

	if( !checkBoxBanner->isChecked() )
		config.set_number( "client-banner-enable", 0 );
	else
		config.set_number( "client-banner-enable", 1 );

	// dns enabled

	if( !checkBoxDNSEnable->isChecked() )
	{
		// disabled

		config.set_number( "client-dns-enable", 0 );
	}
	else
	{
		// enabled

		config.set_number( "client-dns-enable", 1 );

		// dns settings

		if( checkBoxDNSAuto->isChecked() )
		{
			// automatic

			config.set_number( "client-dns-auto", 1 );
		}
		else
		{
			// manual

			config.set_number( "client-dns-auto", 0 );

			// dns server address

			QString DNSServer = lineEditDNSServer->text();
			DNSServer = DNSServer.replace( ' ', "" );

			config.set_string( "client-dns-addr",
				( char * ) DNSServer.ascii(),
				DNSServer.length() );

			// dns suffix

			config.set_string( "client-dns-suffix",
				( char * ) lineEditDNSSuffix->text().ascii(),
				lineEditDNSSuffix->text().length() );
		}
	}

	// authentication mode

	switch( comboBoxAuthMethod->currentItem() )
	{
		case 0:	// hybrid rsa xauth
			config.set_string( "auth-method",
				"hybrid-rsa-xauth", strlen( "hybrid-rsa-xauth" ) );
			break;

		case 1:	// mutual rsa xauth
			config.set_string( "auth-method",
				"mutual-rsa-xauth", strlen( "mutual-rsa-xauth" ) );
			break;

		case 2:	// mutual psk xauth
			config.set_string( "auth-method",
				"mutual-psk-xauth", strlen( "mutual-psk-xauth" ) );
			break;

		case 3:	// mutual rsa
			config.set_string( "auth-method",
				"mutual-rsa", strlen( "mutual-rsa" ) );
			break;

		case 4:	// mutual psk
			config.set_string( "auth-method",
				"mutual-psk", strlen( "mutual-psk" ) );
			break;
	}

	// local identity type

	QString locid = comboBoxLocalIDType->currentText();

	if( !locid.compare( IDTXT_ASN1 ) )
		config.set_string( "ident-client-type",
			"asn1dn", strlen( "asn1dn" ) );

	if( !locid.compare( IDTXT_FQDN ) )
		config.set_string( "ident-client-type",
			"fqdn", strlen( "fqdn" ) );

	if( !locid.compare( IDTXT_UFQDN ) )
		config.set_string( "ident-client-type",
			"ufqdn", strlen( "ufqdn" ) );

	if( !locid.compare( IDTXT_ADDR ) )
		config.set_string( "ident-client-type",
			"address", strlen( "address" ) );

	if( !locid.compare( IDTXT_KEYID ) )
		config.set_string( "ident-client-type",
			"keyid", strlen( "keyid" ) );

	// local identity data

	if( lineEditLocalIDData->isEnabled() )
		config.set_string( "ident-client-data",
			( char * ) lineEditLocalIDData->text().ascii(),
			lineEditLocalIDData->text().length() );
	else
		config.del( "ident-client-data" );

	// remote identity type

	QString rmtid = comboBoxRemoteIDType->currentText();

	if( !rmtid.compare( IDTXT_ASN1 ) )
		config.set_string( "ident-server-type",
			"asn1dn", strlen( "asn1dn" ) );

	if( !rmtid.compare( IDTXT_FQDN ) )
		config.set_string( "ident-server-type",
			"fqdn", strlen( "fqdn" ) );

	if( !rmtid.compare( IDTXT_UFQDN ) )
		config.set_string( "ident-server-type",
			"ufqdn", strlen( "ufqdn" ) );

	if( !rmtid.compare( IDTXT_ADDR ) )
		config.set_string( "ident-server-type",
			"address", strlen( "address" ) );

	if( !rmtid.compare( IDTXT_KEYID ) )
		config.set_string( "ident-server-type",
			"keyid", strlen( "keyid" ) );

	// remote identity data

	if( lineEditRemoteIDData->isEnabled() )
		config.set_string( "ident-server-data",
			( char * ) lineEditRemoteIDData->text().ascii(),
			lineEditRemoteIDData->text().length() );
	else
		config.del( "ident-server-data" );

	// credentials

	if( lineEditCAFile->isEnabled() )
		config.set_string( "auth-server-cert",
			( char * ) lineEditCAFile->text().ascii(),
			lineEditCAFile->text().length() );
	else
		config.del( "auth-server-cert" );

	if( lineEditCertFile->isEnabled() )
		config.set_string( "auth-client-cert",
			( char * ) lineEditCertFile->text().ascii(),
			lineEditCertFile->text().length() );
	else
		config.del( "auth-client-cert" );

	if( lineEditPKeyFile->isEnabled() )
		config.set_string( "auth-client-key",
			( char * ) lineEditPKeyFile->text().ascii(),
			lineEditPKeyFile->text().length() );
	else
		config.del( "auth-client-key" );

	if( lineEditPSK->isEnabled() )
		config.set_string( "auth-mutual-psk",
			( char * ) lineEditPSK->text().ascii(),
			lineEditPSK->text().length() );
	else
		config.del( "auth-mutual-psk" );

	// phase1 exchange type

	if( !comboBoxP1Exchange->currentItem() )
	{
		// main mode

		config.set_string( "phase1-exchange",
			"main",
			strlen( "main" ) );
	}
	else
	{
		// aggressive mode

		config.set_string( "phase1-exchange",
			"aggressive",
			strlen( "aggressive" ) );
	}

	// phase1 dh group

	long dhindex = comboBoxP1DHGroup->currentItem();
	if( comboBoxP1Exchange->currentItem() )
	{
		// aggressive mode ( no auto )
		dhindex++;
	}

	switch( dhindex )
	{
		case 0: // auto
			config.set_number( "phase1-dhgroup", 0 );
			break;

		case 1: // group 1
			config.set_number( "phase1-dhgroup", 1 );
			break;

		case 2: // group 2
			config.set_number( "phase1-dhgroup", 2 );
			break;

		case 3: // group 5
			config.set_number( "phase1-dhgroup", 5 );
			break;

		case 4: // group 14
			config.set_number( "phase1-dhgroup", 14 );
			break;

		case 5: // group 15
			config.set_number( "phase1-dhgroup", 15 );
			break;
	}

	// phase1 cipher algorithm

	config.set_string( "phase1-cipher",
		( char * ) comboBoxP1Cipher->currentText().ascii(),
		comboBoxP1Cipher->currentText().length() );

	// phase1 cipher key length

	config.set_number( "phase1-keylen",
		comboBoxP1Keylen->currentText().toLong() );

	// phase1 hash algorithm

	config.set_string( "phase1-hash",
		( char * ) comboBoxP1Hash->currentText().ascii(),
		comboBoxP1Hash->currentText().length() );

	// phase1 key life time

	config.set_number( "phase1-life-secs",
		lineEditP1LifeTime->text().toLong() );

	// phase1 key life data

	config.set_number( "phase1-life-kbytes",
		lineEditP1LifeData->text().toLong() );

	// phase2 trasform algorithm

	config.set_string( "phase2-transform",
		( char * ) comboBoxP2Transform->currentText().ascii(),
		comboBoxP2Transform->currentText().length() );

	// phase2 transform key length

	config.set_number( "phase2-keylen",
		comboBoxP2Keylen->currentText().toLong() );

	// phase2 hmac algorithm

	config.set_string( "phase2-hmac",
		( char * ) comboBoxP2HMAC->currentText().ascii(),
		comboBoxP2HMAC->currentText().length() );

	// phase2 pfs group

	switch( comboBoxP2PFSGroup->currentItem() )
	{
		case 0:	// disabled
			config.set_number( "phase2-pfsgroup", -1 );
			break;

		case 1: // automatic
			config.set_number( "phase2-pfsgroup", 0 );
			break;

		case 2:	// group 1
			config.set_number( "phase2-pfsgroup", 1 );
			break;

		case 3:	// group 2
			config.set_number( "phase2-pfsgroup", 2 );
			break;

		case 4:	// group 5
			config.set_number( "phase2-pfsgroup", 5 );
			break;

		case 5:	// group 14
			config.set_number( "phase2-pfsgroup", 14 );
			break;

		case 6:	// group 15
			config.set_number( "phase2-pfsgroup", 15 );
			break;
	}

	// phase2 key life time

	config.set_number( "phase2-life-secs",
		lineEditP2LifeTime->text().toLong() );

	// phase2 key life data

	config.set_number( "phase2-life-kbytes",
		lineEditP2LifeData->text().toLong() );

	// ipcomp transform algorithm

	config.set_string( "ipcomp-transform",
		( char * ) comboBoxP2Compress->currentText().ascii(),
		comboBoxP2Compress->currentText().length() );

	// policy configuration

	if( checkBoxPolicyAuto->isChecked() )
	{
		// automatic

		config.set_number( "policy-list-auto", 1 );
	}
	else
	{
		// manual

		config.set_number( "policy-list-auto", 0 );

		// topology entries

		QListViewItem * i = listViewPolicies->firstChild();

		config.del( "policy-list-include" );
		config.del( "policy-list-exclude" );

		while( i != NULL )
		{
			// policy type

			if( i->pixmap( 0 )->serialNumber() ==
			    QPixmap::fromMimeSource( "policy_inc.png" ).serialNumber() )
			{
				// include

				config.add_string( "policy-list-include",
					( char * ) i->text( 1 ).ascii(),
					i->text( 1 ).length() );
			}
			else
			{
				// exlcude

				config.add_string( "policy-list-exclude",
					( char * ) i->text( 1 ).ascii(),
					i->text( 1 ).length() );
			}

			i = i->nextSibling();
		}
	}

	return true;
}

bool site::Verify()
{
	QString errmsg;

	// check remote host

	if( lineEditHost->text().length() < 1 )
		errmsg = "Please enter a valid host name or ip address.";

	// check local id data

	if( lineEditLocalIDData->isEnabled() )
		if( lineEditLocalIDData->text().length() < 1 )
			errmsg = "Please enter valid local ID data.";

	// check remote id data

	if( lineEditRemoteIDData->isEnabled() )
		if( lineEditRemoteIDData->text().length() < 1 )
			errmsg = "Please enter valid remote ID data.";

	// check cert authority file

	if( lineEditCAFile->isEnabled() )
		if( lineEditCAFile->text().length() < 1 )
			errmsg = "Please enter valid certificate authority file path.";

	// check cert file

	if( lineEditCertFile->isEnabled() )
		if( lineEditCertFile->text().length() < 1 )
			errmsg = "Please enter valid certificate file path.";

	// check private key file

	if( lineEditPKeyFile->isEnabled() )
		if( lineEditPKeyFile->text().length() < 1 )
			errmsg = "Please enter valid private key file path.";

	// check pre shared key

	if( lineEditPSK->isEnabled() )
		if( lineEditPSK->text().length() < 1 )
			errmsg = "Please enter valid pre-shared key.";

	// verify policy list

	if( !checkBoxPolicyAuto->isChecked() )
		if( !listViewPolicies->childCount() )
			errmsg = "You must specify at least one remote network resource.";

	if( errmsg.length() )
	{
		QMessageBox m;

		m.critical( this,
			"Site Configuration Error",
			errmsg,
			QMessageBox::Ok,
			QMessageBox::NoButton,
			QMessageBox::NoButton );

		return false;
	}

	return true;
}


void site::Update()
{
	// local adapter mode

	if( !comboBoxAddressMethod->currentItem() )
	{
		// virtual

		checkBoxAddressAuto->setEnabled( true );
		textLabelAddress->setEnabled( true );
		textLabelNetmask->setEnabled( true );

		if( checkBoxAddressAuto->isChecked() )
		{
			lineEditAddress->setEnabled( false );
			lineEditNetmask->setEnabled( false );
		}
		else
		{
			lineEditAddress->setEnabled( true );
			lineEditNetmask->setEnabled( true );
		}
	}
	else
	{
		// direct

		checkBoxAddressAuto->setEnabled( false );
		textLabelAddress->setEnabled( false );
		textLabelNetmask->setEnabled( false );

		lineEditAddress->setEnabled( false );
		lineEditNetmask->setEnabled( false );
	}

	// nat traversal mode

	if( !comboBoxNATTMode->currentItem() )
	{
		// disabled

		textLabelNATTPort->setEnabled( false );
		lineEditNATTPort->setEnabled( false );

		textLabelNATTRate->setEnabled( false );
		lineEditNATTRate->setEnabled( false );
		textLabelNATTSecs->setEnabled( false );
	}
	else
	{
		// not disabled

		textLabelNATTPort->setEnabled( true );
		lineEditNATTPort->setEnabled( true );

		textLabelNATTRate->setEnabled( true );
		lineEditNATTRate->setEnabled( true );
		textLabelNATTSecs->setEnabled( true );
	}

	// ike frag mode

	if( !comboBoxFragMode->currentItem() )
	{
		// disabled

		textLabelFragSize->setEnabled( false );
		lineEditFragSize->setEnabled( false );
	}
	else
	{
		// not disabled

		textLabelFragSize->setEnabled( true );
		lineEditFragSize->setEnabled( true );
	}

	// dns enabled

	if( checkBoxDNSEnable->isChecked() )
	{
		// enabled

		checkBoxDNSAuto->setEnabled( true );

		textLabelDNSServer->setEnabled( true );
		textLabelDNSSuffix->setEnabled( true );

		if( checkBoxDNSAuto->isChecked() )
		{
			lineEditDNSServer->setEnabled( false );
			lineEditDNSSuffix->setEnabled( false );
		}
		else
		{
			lineEditDNSServer->setEnabled( true );
			lineEditDNSSuffix->setEnabled( true );
		}
	}
	else
	{
		// disabled

		checkBoxDNSAuto->setEnabled( false );

		textLabelDNSServer->setEnabled( false );
		lineEditDNSServer->setEnabled( false );

		textLabelDNSSuffix->setEnabled( false );
		lineEditDNSSuffix->setEnabled( false );
	}

	// policy configuration

	if( checkBoxPolicyAuto->isChecked() )
	{
		// automatic

		listViewPolicies->setEnabled( false );

		pushButtonPolicyAdd->setEnabled( false );
		pushButtonPolicyMod->setEnabled( false );
		pushButtonPolicyDel->setEnabled( false );
	}
	else
	{
		// manual

		listViewPolicies->setEnabled( true );

		pushButtonPolicyAdd->setEnabled( true );

		// policy item selection

		if( listViewPolicies->selectedItem() != NULL )
		{
			// have selection

			pushButtonPolicyMod->setEnabled( true );
			pushButtonPolicyDel->setEnabled( true );
		}
		else
		{
			// no selection

			pushButtonPolicyMod->setEnabled( false );
			pushButtonPolicyDel->setEnabled( false );
		}
	}
}

void site::UpdateExchange()
{
	// exchange mode

	if( !comboBoxP1Exchange->currentItem() )
	{
		// main mode ( auto allowed )

		QString text = comboBoxP1DHGroup->currentText();

		comboBoxP1DHGroup->clear();
		comboBoxP1DHGroup->insertItem( "auto" );
		comboBoxP1DHGroup->insertItem( "group 1" );
		comboBoxP1DHGroup->insertItem( "group 2" );
		comboBoxP1DHGroup->insertItem( "group 5" );
		comboBoxP1DHGroup->insertItem( "group 14" );
		comboBoxP1DHGroup->insertItem( "group 15" );

		combobox_setbytext( ( char * ) text.ascii(), comboBoxP1DHGroup );
	}
	else
	{
		// aggressive mode ( auto not allowed )

		QString text = comboBoxP1DHGroup->currentText();

		comboBoxP1DHGroup->clear();
		comboBoxP1DHGroup->insertItem( "group 1" );
		comboBoxP1DHGroup->insertItem( "group 2" );
		comboBoxP1DHGroup->insertItem( "group 5" );
		comboBoxP1DHGroup->insertItem( "group 14" );
		comboBoxP1DHGroup->insertItem( "group 15" );

		combobox_setbytext( ( char * ) text.ascii(), comboBoxP1DHGroup );
	}

	UpdateAuth();
}

void site::UpdateCipher()
{
	// chipher type

	QString text = comboBoxP1Keylen->currentText();

	switch( comboBoxP1Cipher->currentItem() )
	{
		case 1: // aes
		{
			comboBoxP1Keylen->setEnabled( true );
			comboBoxP1Keylen->clear();
			comboBoxP1Keylen->insertItem( "auto" );
			comboBoxP1Keylen->insertItem( "128" );
			comboBoxP1Keylen->insertItem( "192" );
			comboBoxP1Keylen->insertItem( "256" );
			break;
		}

		case 2: // blowfish
		{
			comboBoxP1Keylen->setEnabled( true );
			comboBoxP1Keylen->clear();
			comboBoxP1Keylen->insertItem( "auto" );
			for( long b = 128; b <= 256; b += 8 )
				comboBoxP1Keylen->insertItem(
					QString::number( b, 10 ) );
			break;
		}

		default: // all others
		{
			comboBoxP1Keylen->setCurrentItem( 0 );
			comboBoxP1Keylen->setEnabled( false );
			break;
		}
	}

	if( !comboBoxP1Cipher->currentItem() )
		comboBoxP1Keylen->setCurrentItem( 0 );
	else
		combobox_setbytext( ( char * ) text.ascii(), comboBoxP1Keylen );
}
         
void site::UpdateTransform()
{
	// chipher type

	QString text = comboBoxP2Keylen->currentText();

	switch( comboBoxP2Transform->currentItem() )
	{
		case 1: // aes
		{
			comboBoxP2Keylen->setEnabled( true );
			comboBoxP2Keylen->clear();
			comboBoxP2Keylen->insertItem( "auto" );
			comboBoxP2Keylen->insertItem( "128" );
			comboBoxP2Keylen->insertItem( "192" );
			comboBoxP2Keylen->insertItem( "256" );
			break;
		}

		case 2: // blowfish
		{
			comboBoxP2Keylen->setEnabled( true );
			comboBoxP2Keylen->clear();
			comboBoxP2Keylen->insertItem( "auto" );
			for( long b = 128; b <= 256; b += 8 )
				comboBoxP2Keylen->insertItem(
					QString::number( b, 10 ) );
			break;
		}

		default: // all others
		{
			comboBoxP2Keylen->setCurrentItem( 0 );
			comboBoxP2Keylen->setEnabled( false );
			break;
		}
	}

	if( !comboBoxP2Transform->currentItem() )
		comboBoxP2Keylen->setCurrentItem( 0 );
	else
		combobox_setbytext( ( char * ) text.ascii(), comboBoxP2Keylen );
}

void site::UpdateAuth()
{
	// local identity

	QString locid = comboBoxLocalIDType->currentText();

	switch( comboBoxAuthMethod->currentItem() )
	{
		case 0: // hybrid rsa xauth
		case 2: // mutual psk xauth
		case 4: // mutual psk
		{

			if( !comboBoxP1Exchange->currentItem() )
			{
				// main mode

				comboBoxLocalIDType->clear();
				comboBoxLocalIDType->insertItem( IDTXT_ADDR );
			}
			else
			{
				// aggressive mode

				comboBoxLocalIDType->clear();
				comboBoxLocalIDType->insertItem( IDTXT_FQDN );
				comboBoxLocalIDType->insertItem( IDTXT_UFQDN );
				comboBoxLocalIDType->insertItem( IDTXT_ADDR );
				comboBoxLocalIDType->insertItem( IDTXT_KEYID );
			}

			break;
		}

		case 1: // mutual rsa xauth
		case 3: // mutual rsa
		{
			if( !comboBoxP1Exchange->currentItem() )
			{
				// main mode

				comboBoxLocalIDType->clear();
				comboBoxLocalIDType->insertItem( IDTXT_ASN1 );
				comboBoxLocalIDType->insertItem( IDTXT_ADDR );
			}
			else
			{
				// aggressive mode

				comboBoxLocalIDType->clear();
				comboBoxLocalIDType->insertItem( IDTXT_ASN1 );
				comboBoxLocalIDType->insertItem( IDTXT_FQDN );
				comboBoxLocalIDType->insertItem( IDTXT_UFQDN );
				comboBoxLocalIDType->insertItem( IDTXT_ADDR );
				comboBoxLocalIDType->insertItem( IDTXT_KEYID );
			}

			break;
		}
	}

	// attempt to select old value, reset on failure

	if( !combobox_setbytext( ( char * ) locid.ascii(), comboBoxLocalIDType ) )
	{
		lineEditLocalIDData->clear();
		checkBoxLocalIDOption->setChecked( true );
	}

	// remote identity

	QString rmtid = comboBoxRemoteIDType->currentText();

	switch( comboBoxAuthMethod->currentItem() )
	{
		case 0: // hybrid rsa xauth
		case 1: // mutual rsa xauth
		case 3: // mutual rsa
		{
			if( !comboBoxP1Exchange->currentItem() )
			{
				// main mode

				comboBoxRemoteIDType->clear();
				comboBoxRemoteIDType->insertItem( IDTXT_ASN1 );
				comboBoxRemoteIDType->insertItem( IDTXT_ADDR );
			}
			else
			{
				// aggressive mode

				comboBoxRemoteIDType->clear();
				comboBoxRemoteIDType->insertItem( IDTXT_ASN1 );
				comboBoxRemoteIDType->insertItem( IDTXT_FQDN );
				comboBoxRemoteIDType->insertItem( IDTXT_UFQDN );
				comboBoxRemoteIDType->insertItem( IDTXT_ADDR );
				comboBoxRemoteIDType->insertItem( IDTXT_KEYID );
			}

			break;
		}

		case 2: // mutual psk xauth
		case 4: // mutual psk
		{
			if( !comboBoxP1Exchange->currentItem() )
			{
				// main mode

				comboBoxRemoteIDType->clear();
				comboBoxRemoteIDType->insertItem( IDTXT_ADDR );
			}
			else
			{
				// aggressive mode

				comboBoxRemoteIDType->clear();
				comboBoxRemoteIDType->insertItem( IDTXT_FQDN );
				comboBoxRemoteIDType->insertItem( IDTXT_UFQDN );
				comboBoxRemoteIDType->insertItem( IDTXT_ADDR );
				comboBoxRemoteIDType->insertItem( IDTXT_KEYID );
			}

			break;
		}
	}

	// attempt to select old value, reset on failure

	if( !combobox_setbytext( ( char * ) rmtid.ascii(), comboBoxRemoteIDType ) )
	{
		lineEditRemoteIDData->clear();
		checkBoxRemoteIDOption->setChecked( true );
	}

	// authentication credentials

	switch( comboBoxAuthMethod->currentItem() )
	{
		case 0: // hybrid rsa xauth
		{
			lineEditCAFile->setEnabled( true );
			toolButtonCAFile->setEnabled( true );
			
			lineEditCertFile->setEnabled( false );
			toolButtonCertFile->setEnabled( false );
			
			lineEditPKeyFile->setEnabled( false );
			toolButtonPKeyFile->setEnabled( false );
			
			lineEditPSK->setEnabled( false );

			break;
		}

		case 1: // mutual rsa xauth
		case 3: // mutual rsa
		{
			lineEditCAFile->setEnabled( true );
			toolButtonCAFile->setEnabled( true );
			
			lineEditCertFile->setEnabled( true );
			toolButtonCertFile->setEnabled( true );
			
			lineEditPKeyFile->setEnabled( true );
			toolButtonPKeyFile->setEnabled( true );
			
			lineEditPSK->setEnabled( false );

			break;
		}

		case 2: // mutual psk xauth
		case 4: // mutual psk
		{
			lineEditCAFile->setEnabled( false );
			toolButtonCAFile->setEnabled( false );
			
			lineEditCertFile->setEnabled( false );
			toolButtonCertFile->setEnabled( false );
			
			lineEditPKeyFile->setEnabled( false );
			toolButtonPKeyFile->setEnabled( false );
			
			lineEditPSK->setEnabled( true );

			break;
		}
	}

	UpdateLocalID();
	UpdateRemoteID();
}

void site::UpdateLocalID()
{
	QString type = comboBoxLocalIDType->currentText();

	if( !type.compare( IDTXT_ASN1 ) )
	{
		textLabelLocalIDData->setText( "ASN.1 DN String" );
		checkBoxLocalIDOption->setHidden( false );
		checkBoxLocalIDOption->setText( "Use the subject in the client certificate" );
	}

	if( !type.compare( IDTXT_FQDN ) )
	{
		textLabelLocalIDData->setText( "FQDN String" );
		checkBoxLocalIDOption->setHidden( true );
	}

	if( !type.compare( IDTXT_UFQDN ) )
	{
		textLabelLocalIDData->setText( "UFQDN String" );
		checkBoxLocalIDOption->setHidden( true );
	}

	if( !type.compare( IDTXT_ADDR ) )
	{
		textLabelLocalIDData->setText( "Address String" );
		checkBoxLocalIDOption->setHidden( false );
		checkBoxLocalIDOption->setText( "Use discovered local host address" );
	}

	if( !type.compare( IDTXT_KEYID ) )
	{
		textLabelLocalIDData->setText( "Key ID String" );
		checkBoxLocalIDOption->setHidden( true );
	}

	if( checkBoxLocalIDOption->isHidden() )
		lineEditLocalIDData->setEnabled( true );
	else
		lineEditLocalIDData->setEnabled( !checkBoxLocalIDOption->isChecked() );
}

void site::UpdateRemoteID()
{
	QString type = comboBoxRemoteIDType->currentText();

	if( !type.compare( IDTXT_ASN1 ) )
	{
		textLabelRemoteIDData->setText( "ASN.1 DN String" );
		checkBoxRemoteIDOption->setHidden( false );
		checkBoxRemoteIDOption->setText( "Use the subject in the received certificate" );
	}

	if( !type.compare( IDTXT_FQDN ) )
	{
		textLabelRemoteIDData->setText( "FQDN String" );
		checkBoxRemoteIDOption->setHidden( true );
	}

	if( !type.compare( IDTXT_UFQDN ) )
	{
		textLabelRemoteIDData->setText( "UFQDN String" );
		checkBoxRemoteIDOption->setHidden( true );
	}

	if( !type.compare( IDTXT_ADDR ) )
	{
		textLabelRemoteIDData->setText( "Address String" );
		checkBoxRemoteIDOption->setHidden( false );
		checkBoxRemoteIDOption->setText( "Use discovered remote host address" );
	}

	if( !type.compare( IDTXT_KEYID ) )
	{
		textLabelRemoteIDData->setText( "Key ID String" );
		checkBoxRemoteIDOption->setHidden( true );
	}

	if( checkBoxRemoteIDOption->isHidden() )
		lineEditRemoteIDData->setEnabled( true );
	else
		lineEditRemoteIDData->setEnabled( !checkBoxRemoteIDOption->isChecked() );
}

void site::SelectLocalID()
{                        
	lineEditLocalIDData->clear();
	checkBoxLocalIDOption->setChecked( true );

	UpdateLocalID();
}

void site::SelectRemoteID()
{
	lineEditRemoteIDData->clear();
	checkBoxRemoteIDOption->setChecked( true );

	UpdateRemoteID();
}


void site::InputCAFile()
{
	QString types(
		"OpenSSL Files (*.key *.pem *.crt *.crt);;"
		"PKCS #12 Files (*.p12 *.pfx);;"
		"All files (*)" );

	QFileDialog f( this );
	f.setDir( ikea.cert_path() );
	f.setFilters( types );

	if( f.exec() == QDialog::Accepted )
		lineEditCAFile->setText( f.selectedFile() );
}


void site::InputCertFile()
{
	QString types(
		"OpenSSL Files (*.key *.pem *.crt *.crt);;"
		"PKCS #12 Files (*.p12 *.pfx);;"
		"All files (*)" );

	QFileDialog f( this );
	f.setDir( ikea.cert_path() );
	f.setFilters( types );

	if( f.exec() == QDialog::Accepted )
		lineEditCertFile->setText( f.selectedFile() );
}


void site::InputPKeyFile()
{
	QString types(
		"OpenSSL Files (*.key *.pem *.crt *.crt);;"
		"PKCS #12 Files (*.p12 *.pfx);;"
		"All files (*)" );

	QFileDialog f( this );
	f.setDir( ikea.cert_path() );
	f.setFilters( types );

	if( f.exec() == QDialog::Accepted )
		lineEditPKeyFile->setText( f.selectedFile() );
}


void site::VerifyAccept()
{
	if( Verify() )
		accept();

	return;
}
