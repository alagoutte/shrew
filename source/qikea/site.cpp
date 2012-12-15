
/*
 * Copyright (c) 2007
 *      Shrew Soft Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Redistributions in any form must be accompanied by information on
 *    how to obtain complete source code for the software and any
 *    accompanying software that uses the software.  The source code
 *    must either be included in the distribution or be available for no
 *    more than the cost of distribution plus a nominal fee, and must be
 *    freely redistributable under reasonable conditions.  For an
 *    executable file, complete source code means the source code for all
 *    modules it contains.  It does not include source code for modules or
 *    files that typically accompany the major components of the operating
 *    system on which the executable file runs.
 *
 * THIS SOFTWARE IS PROVIDED BY SHREW SOFT INC ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR
 * NON-INFRINGEMENT, ARE DISCLAIMED.  IN NO EVENT SHALL SHREW SOFT INC
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 * AUTHOR : Matthew Grooms
 *          mgrooms@shrew.net
 *
 */

#include "qikea.h"

#define EXCH_AGGR_MODE		0
#define EXCH_MAIN_MODE		1

#define AUTH_HYBRID_RSA_XAUTH	0
#define AUTH_HYBRID_GRP_XAUTH	1
#define AUTH_MUTUAL_RSA_XAUTH	2
#define AUTH_MUTUAL_PSK_XAUTH	3
#define AUTH_MUTUAL_RSA		4
#define AUTH_MUTUAL_PSK		5

#define AMTXT_VIRTUAL	"Use a virtual adapter and assigned address"
#define AMTXT_RANDOM	"Use a virtual adapter and random address"
#define AMTXT_DIRECT	"Use an existing adapter and current address"

#define IDTXT_NONE	"No Identity"
#define IDTXT_ANY	"Any"
#define IDTXT_ASN1	"ASN.1 Distinguished Name"
#define IDTXT_FQDN	"Fully Qualified Domain Name"
#define IDTXT_UFQDN	"User Fully Qualified Domain Name"
#define IDTXT_ADDR	"IP Address"
#define IDTXT_KEYID	"Key Identifier"

#define TREE_INCLUDE	( QTreeWidgetItem::UserType + 1 )
#define TREE_EXCLUDE	( QTreeWidgetItem::UserType + 2 )

bool combobox_setbytext( QString text, QComboBox * cbox )
{
	long index = 0;
	long count = cbox->count();

	for( ; index < count; index++ )
	{
		if( text == cbox->itemText( index ) )
		{
			cbox->setCurrentIndex( index );
			return true;
		}
	}

	return false;
}

bool dhgrp_to_string( long & dhgrp, QString & string )
{
	switch( dhgrp )
	{
		case -1:
			string = "disabled";
			break;

		case 0:
			string = "auto";
			break;

		case 1:
			string = "group 1";
			break;

		case 2:
			string = "group 2";
			break;

		case 5:
			string = "group 5";
			break;

		case 14:
			string = "group 14";
			break;

		case 15:
			string = "group 15";
			break;

		case 16:
			string = "group 16";
			break;

		case 17:
			string = "group 17";
			break;

		case 18:
			string = "group 18";
			break;

		default:
			return false;
	}

	return true;
}

bool string_to_dhgrp( QString & string, long & dhgrp )
{
	if( string == "disabled" )
		dhgrp = -1;

	if( string == "auto" )
		dhgrp = 0;

	if( string == "group 1" )
		dhgrp = 1;

	if( string == "group 2" )
		dhgrp = 2;

	if( string == "group 5" )
		dhgrp = 5;

	if( string == "group 14" )
		dhgrp = 14;

	if( string == "group 15" )
		dhgrp = 15;

	if( string == "group 16" )
		dhgrp = 16;

	if( string == "group 17" )
		dhgrp = 17;

	if( string == "group 18" )
		dhgrp = 18;

	return true;
}

void _qikeaSite::init()
{
	comboBoxConfigMethod->setCurrentIndex( 1 );

	lineEditAddress->setInputMask( "009 . 009 . 009 . 009" );
	lineEditAddress->setText( "0.0.0.0" );

	lineEditNetmask->setInputMask( "009 . 009 . 009 . 009" );
	lineEditNetmask->setText( "255.255.255.255" );

	lineEditDNSServer1->setInputMask( "009 . 009 . 009 . 009" );
	lineEditDNSServer1->setText( "0.0.0.0" );

	lineEditDNSServer2->setInputMask( "009 . 009 . 009 . 009" );
	lineEditDNSServer2->setText( "0.0.0.0" );

	lineEditDNSServer3->setInputMask( "009 . 009 . 009 . 009" );
	lineEditDNSServer3->setText( "0.0.0.0" );

	lineEditDNSServer4->setInputMask( "009 . 009 . 009 . 009" );
	lineEditDNSServer4->setText( "0.0.0.0" );

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

	updateGeneral( false, false );
	updateAuthentication();
	updatePhase1();
	updatePhase2();
	updatePolicy();
}

void _qikeaSite::policyAdd()
{
	qikeaTopology t( this );
	if( t.exec() == QDialog::Rejected )
		return;

	// address and netmask

	QString address = t.lineEditAddress->text();
	address = address.replace( ' ', "" );

	QString netmask = t.lineEditNetmask->text();
	netmask = netmask.replace( ' ', "" );

	QString text = address + " / " + netmask;

	// create item
	
	if( !t.comboBoxType->currentIndex() )
	{
		QTreeWidgetItem * i = new QTreeWidgetItem( treeWidgetPolicies, TREE_INCLUDE );
		i->setText( 0, text );
		i->setIcon( 0, QIcon( ":/png/policy_inc.png" ) );
	}
	else
	{
		QTreeWidgetItem * i = new QTreeWidgetItem( treeWidgetPolicies, TREE_EXCLUDE );
		i->setText( 0, text );
		i->setIcon( 0, QIcon( ":/png/policy_exc.png" ) );
	}
}

void _qikeaSite::policyModify()
{
	QTreeWidgetItem * i = treeWidgetPolicies->currentItem();
	if( i == NULL )
		return;

	QString text = i->text( 0 );

	QString address = text.section( '/', 0, 0 );
	QString netmask = text.section( '/', 1, 1 );

	address = address.replace( ' ', "" );
	netmask = netmask.replace( ' ', "" );

	qikeaTopology t( this );

	t.lineEditAddress->setText( address );
	t.lineEditNetmask->setText( netmask );

	if( i->type() == TREE_INCLUDE )
		t.comboBoxType->setCurrentIndex( 0 );
	else
		t.comboBoxType->setCurrentIndex( 1 );

	if( t.exec() == QDialog::Rejected )
		return;

	delete i;

	// address and netmask

	text  = t.lineEditAddress->text();
	text += " / ";
	text += t.lineEditNetmask->text();

	// set icon

	if( !t.comboBoxType->currentIndex() )
	{
		i = new QTreeWidgetItem( treeWidgetPolicies, TREE_INCLUDE );
		i->setText( 0, text );
		i->setIcon( 0, QIcon( ":/png/policy_inc.png" ) );
	}
	else
	{
		i = new QTreeWidgetItem( treeWidgetPolicies, TREE_EXCLUDE );
		i->setText( 0, text );
		i->setIcon( 0, QIcon( ":/png/policy_exc.png" ) );
	}
}

void _qikeaSite::policyDelete()
{
	QTreeWidgetItem * i = treeWidgetPolicies->currentItem();
	if( i != NULL )
		delete i;
}

bool _qikeaSite::load( CONFIG & config )
{
	QString string;
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
	{
		if( !strcmp( text, "disabled" ) )
			comboBoxConfigMethod->setCurrentIndex( 0 );

		if( !strcmp( text, "pull" ) )
			comboBoxConfigMethod->setCurrentIndex( 1 );

		if( !strcmp( text, "push" ) )
			comboBoxConfigMethod->setCurrentIndex( 2 );

		if( !strcmp( text, "dhcp" ) )
			comboBoxConfigMethod->setCurrentIndex( 3 );
	}

	// update dialog

	updateGeneral( false, false );

	// local adapter mode ( default virtual )

	if( config.get_string( "client-iface",
		text, MAX_CONFSTRING, 0 ) )
	{
		if( !strcmp( text, "virtual" ) )
			combobox_setbytext( AMTXT_VIRTUAL, comboBoxAddressMethod );

		if( !strcmp( text, "random" ) )
			combobox_setbytext( AMTXT_RANDOM, comboBoxAddressMethod );

		if( !strcmp( text, "direct" ) )
			combobox_setbytext( AMTXT_DIRECT, comboBoxAddressMethod );
	}

	if( !strcmp( text, "virtual" ) || !strcmp( text, "random" ) )
	{
		// virtual adapter mtu

		numb = 0;
		if( config.get_number( "network-mtu-size", &numb ) )
			lineEditMTU->setText( QString::number( numb, 10 ) );

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

	if( comboBoxNATTMode->currentIndex() )
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

	if( comboBoxFragMode->currentIndex() )
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
	config.get_number( "client-banner-enable", &numb );
	if( numb )
		checkBoxBanner->setChecked( true );
	else
		checkBoxBanner->setChecked( false );

	// dns used ( default used )

	numb = 1;
	config.get_number( "client-dns-used", &numb );

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
			// automatic dns server addresses

			checkBoxDNSAuto->setChecked( true );
		}
		else
		{
			// manual dns server addresses

			checkBoxDNSAuto->setChecked( false );

			long index = 0;

			if( config.get_string( "client-dns-addr",
				text, MAX_CONFSTRING, index++ ) )
				lineEditDNSServer1->setText( text );

			if( config.get_string( "client-dns-addr",
				text, MAX_CONFSTRING, index++ ) )
				lineEditDNSServer2->setText( text );

			if( config.get_string( "client-dns-addr",
				text, MAX_CONFSTRING, index++ ) )
				lineEditDNSServer3->setText( text );

			if( config.get_string( "client-dns-addr",
				text, MAX_CONFSTRING, index++ ) )
				lineEditDNSServer4->setText( text );
		}

		numb = 1;
		config.get_number( "client-dns-suffix-auto", &numb );

		if( numb )
		{
			// automatic dns default suffix

			checkBoxSuffixAuto->setChecked( true );
		}
		else
		{
			// manual dns default suffix

			checkBoxSuffixAuto->setChecked( false );

			if( config.get_string( "client-dns-suffix",
				text, MAX_CONFSTRING, 0 ) )
				lineEditDNSSuffix->setText( text );
		}
	}

	// update dialog

	updateGeneral( false, false );

	// authentication mode ( default hybrid rsa xauth )

	if( config.get_string( "auth-method",
		text, MAX_CONFSTRING, 0 ) )
	{
		if( !strcmp( "hybrid-rsa-xauth", text ) )
			comboBoxAuthMethod->setCurrentIndex( 0 );

		if( !strcmp( "hybrid-grp-xauth", text ) )
			comboBoxAuthMethod->setCurrentIndex( 1 );

		if( !strcmp( "mutual-rsa-xauth", text ) )
			comboBoxAuthMethod->setCurrentIndex( 2 );

		if( !strcmp( "mutual-psk-xauth", text ) )
			comboBoxAuthMethod->setCurrentIndex( 3 );

		if( !strcmp( "mutual-rsa", text ) )
			comboBoxAuthMethod->setCurrentIndex( 4 );

		if( !strcmp( "mutual-psk", text ) )
			comboBoxAuthMethod->setCurrentIndex( 5 );
	}

	// update dialog

	updateAuthMethod();

	// local identity type

	if( config.get_string( "ident-client-type",
		text, MAX_CONFSTRING, 0 ) )
	{
		if( !strcmp( "none", text ) )
			combobox_setbytext( IDTXT_NONE, comboBoxLocalIDType );

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
		if( !strcmp( "any", text ) )
			combobox_setbytext( IDTXT_ANY, comboBoxRemoteIDType );

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

	if( config.get_string( "auth-server-cert-name",
		text, MAX_CONFSTRING, 0 ) )
		lineEditCAName->setText( text );

	if( config.get_string( "auth-client-cert-name",
		text, MAX_CONFSTRING, 0 ) )
		lineEditCertName->setText( text );

	if( config.get_string( "auth-client-key-name",
		text, MAX_CONFSTRING, 0 ) )
		lineEditPKeyName->setText( text );

	BDATA psk;
	if( config.get_binary( "auth-mutual-psk", psk ) )
	{
		psk.add( "", 1 );
		lineEditPSK->setText( psk.text() );
	}

	// update dialog

	updateAuthentication();

	// phase1 exchange type ( default main )

	if( config.get_string( "phase1-exchange",
		text, MAX_CONFSTRING, 0 ) )
	{
		if( !strcmp( text, "aggressive" ) )
			comboBoxP1Exchange->setCurrentIndex( EXCH_AGGR_MODE );

		if( !strcmp( text, "main" ) )
			comboBoxP1Exchange->setCurrentIndex( EXCH_MAIN_MODE );
	}

	// update dialog

	updatePhase1();

	// phase1 dh group ( default auto )

	numb = 0;
	config.get_number( "phase1-dhgroup", &numb );

	if( dhgrp_to_string( numb, string ) )
		combobox_setbytext( string, comboBoxP1DHGroup );

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

	// phase1 checkpoint vendor option

	numb = 1;
	config.get_number( "vendor-chkpt-enable", &numb );
	if( numb )
		checkBoxCheckpointID->setChecked( true );
	else
		checkBoxCheckpointID->setChecked( false );

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

	if( dhgrp_to_string( numb, string ) )
		combobox_setbytext( string, comboBoxP2PFSGroup );

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

	// policy level option ( default auto )

	if( config.get_string( "policy-level",
		text, MAX_CONFSTRING, 0 ) )
		combobox_setbytext( text, comboBoxPolicyLevel );

	// policy nailed sa option ( defailt off )

	numb = 0;
	config.get_number( "policy-nailed", &numb );
	if( numb )
		checkBoxPolicyNailed->setChecked( true );
	else
		checkBoxPolicyNailed->setChecked( false );
		

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
			QTreeWidgetItem * i = new QTreeWidgetItem( treeWidgetPolicies, TREE_EXCLUDE );
			i->setText( 0, text );
			i->setIcon( 0, QIcon( ":/png/policy_exc.png" ) );
		}

		// topology include list

		index = 0;

		while( config.get_string( "policy-list-include",
			text, MAX_CONFSTRING, index++ ) )
		{
			QTreeWidgetItem * i = new QTreeWidgetItem( treeWidgetPolicies, TREE_INCLUDE );
			i->setText( 0, text );
			i->setIcon( 0, QIcon( ":/png/policy_inc.png" ) );
		}
	}

	// update dialog

	updatePhase1();
	updatePhase2();
	updatePolicy();

	return true;
}

bool _qikeaSite::save( CONFIG & config )
{
	// remote name or address

	config.set_string( "network-host",
		lineEditHost->text().toAscii(),
		lineEditHost->text().length() );

	// remote ike port

	config.set_number( "network-ike-port",
		lineEditPort->text().toLong() );

	// remote config method

	switch( comboBoxConfigMethod->currentIndex() )
	{
		case 0:	// disabled
			config.set_string( "client-auto-mode",
				"disabled", strlen( "disabled" ) );
			break;

		case 1: // ike config pull
			config.set_string( "client-auto-mode",
				"pull", strlen( "pull" ) );
			break;

		case 2:	// ike config push
			config.set_string( "client-auto-mode",
				"push", strlen( "push" ) );
			break;

		case 3:	// dhcp over ipsec
			config.set_string( "client-auto-mode",
				"dhcp", strlen( "dhcp" ) );
			break;
	}

	// local adapter mode

	QString amode = comboBoxAddressMethod->currentText();

	if( !amode.compare( AMTXT_VIRTUAL ) )
	{
		// direct mode

		config.set_string( "client-iface",
			"virtual",
			strlen( "virtual" ) );
	}

	if( !amode.compare( AMTXT_RANDOM ) )
	{
		// direct mode

		config.set_string( "client-iface",
			"random",
			strlen( "random" ) );
	}

	if( !amode.compare( AMTXT_DIRECT ) )
	{
		// direct mode

		config.set_string( "client-iface",
			"direct",
			strlen( "direct" ) );
	}


	if( !amode.compare( AMTXT_VIRTUAL ) || !amode.compare( AMTXT_RANDOM ) )
	{
		// adapter mtu

		config.set_number( "network-mtu-size",
			lineEditMTU->text().toLong() );

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
				Address.toAscii(),
				Address.length() );

			// adapter netmask

			QString Netmask = lineEditNetmask->text();
			Netmask = Netmask.replace( ' ', "" );

			config.set_string( "client-ip-mask",
				Netmask.toAscii(),
				Netmask.length() );
		}
	}

#ifdef OPT_NATT

	// nat traversal mode

	config.set_string( "network-natt-mode",
		comboBoxNATTMode->currentText().toAscii(),
		comboBoxNATTMode->currentText().length() );

	// natt not disabled

	if( comboBoxNATTMode->currentIndex() )
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
		comboBoxFragMode->currentText().toAscii(),
		comboBoxFragMode->currentText().length() );

	// ike frag not disabled

	if( comboBoxFragMode->currentIndex() )
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

		config.set_number( "client-dns-used", 0 );
	}
	else
	{
		// enabled

		config.set_number( "client-dns-used", 1 );

		// dns settings

		if( checkBoxDNSAuto->isChecked() )
		{
			// automatic dns server addresses

			config.set_number( "client-dns-auto", 1 );
		}
		else
		{
			// manual dns server addresses

			config.set_number( "client-dns-auto", 0 );

			config.del( "client-dns-addr" );

			QString DNSServer;

			DNSServer = lineEditDNSServer1->text();
			DNSServer = DNSServer.replace( ' ', "" );

			if( inet_addr( DNSServer.toAscii() ) )
				config.add_string( "client-dns-addr",
					DNSServer.toAscii(),
					DNSServer.length() );

			DNSServer = lineEditDNSServer2->text();
			DNSServer = DNSServer.replace( ' ', "" );

			if( inet_addr( DNSServer.toAscii() ) )
				config.add_string( "client-dns-addr",
					DNSServer.toAscii(),
					DNSServer.length() );

			DNSServer = lineEditDNSServer3->text();
			DNSServer = DNSServer.replace( ' ', "" );

			if( inet_addr( DNSServer.toAscii() ) )
				config.add_string( "client-dns-addr",
					DNSServer.toAscii(),
					DNSServer.length() );

			DNSServer = lineEditDNSServer4->text();
			DNSServer = DNSServer.replace( ' ', "" );

			if( inet_addr( DNSServer.toAscii() ) )
				config.add_string( "client-dns-addr",
					DNSServer.toAscii(),
					DNSServer.length() );
		}

		if( checkBoxSuffixAuto->isChecked() )
		{
			// automatic dns domain suffix

			config.set_number( "client-dns-suffix-auto", 1 );
		}
		else
		{
			// manual dns domain suffix

			config.set_number( "client-dns-suffix-auto", 0 );

			config.del( "client-dns-suffix" );

			config.set_string( "client-dns-suffix",
				lineEditDNSSuffix->text().toAscii(),
				lineEditDNSSuffix->text().length() );
		}
	}

	// authentication mode

	switch( comboBoxAuthMethod->currentIndex() )
	{
		case AUTH_HYBRID_RSA_XAUTH:
			config.set_string( "auth-method",
				"hybrid-rsa-xauth", strlen( "hybrid-rsa-xauth" ) );
			break;

		case AUTH_HYBRID_GRP_XAUTH:
			config.set_string( "auth-method",
				"hybrid-rsa-xauth", strlen( "hybrid-grp-xauth" ) );
			break;

		case AUTH_MUTUAL_RSA_XAUTH:
			config.set_string( "auth-method",
				"mutual-rsa-xauth", strlen( "mutual-rsa-xauth" ) );
			break;

		case AUTH_MUTUAL_PSK_XAUTH:
			config.set_string( "auth-method",
				"mutual-psk-xauth", strlen( "mutual-psk-xauth" ) );
			break;

		case AUTH_MUTUAL_RSA:
			config.set_string( "auth-method",
				"mutual-rsa", strlen( "mutual-rsa" ) );
			break;

		case AUTH_MUTUAL_PSK:
			config.set_string( "auth-method",
				"mutual-psk", strlen( "mutual-psk" ) );
			break;
	}

	// local identity type

	QString locid = comboBoxLocalIDType->currentText();

	if( !locid.compare( IDTXT_NONE ) )
		config.set_string( "ident-client-type",
			"none", strlen( "none" ) );

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
			lineEditLocalIDData->text().toAscii(),
			lineEditLocalIDData->text().length() );
	else
		config.del( "ident-client-data" );

	// remote identity type

	QString rmtid = comboBoxRemoteIDType->currentText();

	if( !rmtid.compare( IDTXT_ANY ) )
		config.set_string( "ident-server-type",
			"any", strlen( "any" ) );

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
			lineEditRemoteIDData->text().toAscii(),
			lineEditRemoteIDData->text().length() );
	else
		config.del( "ident-server-data" );

	// credentials

	if( pathCAFile.size() )
	{
		config.set_string( "auth-server-cert-name",
			lineEditCAName->text().toAscii(),
			lineEditCAName->text().length() );

		BDATA fileData;
		fileData.file_load( pathCAFile.toAscii() );
		config.set_binary( "auth-server-cert-data",
			fileData );
	}
	else
	{
		if( lineEditCAName->text().isEmpty() )
		{
			config.del( "auth-server-cert-name" );
			config.del( "auth-server-cert-data" );
		}
	}

	if( pathCertFile.size() )
	{
		config.set_string( "auth-client-cert-name",
			lineEditCertName->text().toAscii(),
			lineEditCertName->text().length() );

		BDATA fileData;
		fileData.file_load( pathCertFile.toAscii() );
		config.set_binary( "auth-client-cert-data",
			fileData );
	}
	else
	{
		if( lineEditCertName->text().isEmpty() )
		{
			config.del( "auth-client-cert-name" );
			config.del( "auth-client-cert-data" );
		}
	}

	if( pathPKeyFile.size() )
	{
		config.set_string( "auth-client-key-name",
			lineEditPKeyName->text().toAscii(),
			lineEditPKeyName->text().length() );

		BDATA fileData;
		fileData.file_load( pathPKeyFile.toAscii() );
		config.set_binary( "auth-client-key-data",
			fileData );
	}
	else
	{
		if( lineEditPKeyName->text().isEmpty() )
		{
			config.del( "auth-client-key-name" );
			config.del( "auth-client-key-data" );
		}
	}

	if( lineEditPSK->isEnabled() )
	{
		BDATA psk;
		psk.set(
			( const char * ) lineEditPSK->text().toAscii(),
			lineEditPSK->text().length() );
		config.set_binary( "auth-mutual-psk", psk );
	}
	else
		config.del( "auth-mutual-psk" );

	// phase1 exchange type

	if( comboBoxP1Exchange->currentIndex() == EXCH_AGGR_MODE )
		config.set_string( "phase1-exchange",
			"aggressive", strlen( "aggressive" ) );

	if( comboBoxP1Exchange->currentIndex() == EXCH_MAIN_MODE )
		config.set_string( "phase1-exchange",
			"main",	strlen( "main" ) );

	// phase1 dh group

	QString string;
	long dhgrp;
	string = comboBoxP1DHGroup->currentText();
	string_to_dhgrp( string, dhgrp );
	config.set_number( "phase1-dhgroup", dhgrp );

	// phase1 cipher algorithm

	config.set_string( "phase1-cipher",
		comboBoxP1Cipher->currentText().toAscii(),
		comboBoxP1Cipher->currentText().length() );

	// phase1 cipher key length

	config.set_number( "phase1-keylen",
		comboBoxP1Keylen->currentText().toLong() );

	// phase1 hash algorithm

	config.set_string( "phase1-hash",
		comboBoxP1Hash->currentText().toAscii(),
		comboBoxP1Hash->currentText().length() );

	// phase1 key life time

	config.set_number( "phase1-life-secs",
		lineEditP1LifeTime->text().toLong() );

	// phase1 key life data

	config.set_number( "phase1-life-kbytes",
		lineEditP1LifeData->text().toLong() );

	// phase1 Checkpoint vendor option

	if( !checkBoxCheckpointID->isChecked() )
		config.set_number( "vendor-chkpt-enable", 0 );
	else
		config.set_number( "vendor-chkpt-enable", 1 );

	// phase2 trasform algorithm

	config.set_string( "phase2-transform",
		comboBoxP2Transform->currentText().toAscii(),
		comboBoxP2Transform->currentText().length() );

	// phase2 transform key length

	config.set_number( "phase2-keylen",
		comboBoxP2Keylen->currentText().toLong() );

	// phase2 hmac algorithm

	config.set_string( "phase2-hmac",
		comboBoxP2HMAC->currentText().toAscii(),
		comboBoxP2HMAC->currentText().length() );

	// phase2 pfs group

	string = comboBoxP2PFSGroup->currentText();
	string_to_dhgrp( string, dhgrp );
	config.set_number( "phase2-pfsgroup", dhgrp );

	// phase2 key life time

	config.set_number( "phase2-life-secs",
		lineEditP2LifeTime->text().toLong() );

	// phase2 key life data

	config.set_number( "phase2-life-kbytes",
		lineEditP2LifeData->text().toLong() );

	// ipcomp transform algorithm

	config.set_string( "ipcomp-transform",
		comboBoxP2Compress->currentText().toAscii(),
		comboBoxP2Compress->currentText().length() );

	// policy level option

	config.set_string( "policy-level",
		comboBoxPolicyLevel->currentText().toAscii(),
		comboBoxPolicyLevel->currentText().length() );

	// policy nailed sa option

	if( !checkBoxPolicyNailed->isChecked() )
		config.set_number( "policy-nailed", 0 );
	else
		config.set_number( "policy-nailed", 1 );

	if( checkBoxPolicyAuto->isChecked() )
	{
		// automatic

		config.set_number( "policy-list-auto", 1 );
	}
	else
	{
		// manual

		config.set_number( "policy-list-auto", 0 );

		config.del( "policy-list-include" );
		config.del( "policy-list-exclude" );

		// topology entries

		QTreeWidgetItem * rootItem = treeWidgetPolicies->invisibleRootItem();

		long count = rootItem->childCount();
		long index = 0;

		for( ; index < count; index++ )
		{
			QTreeWidgetItem * i = rootItem->child( index );

			// policy type

			if( i->type() == TREE_INCLUDE )
			{
				// include

				config.add_string( "policy-list-include",
					i->text( 0 ).toAscii(),
					i->text( 0 ).length() );
			}

			if( i->type() == TREE_EXCLUDE )
			{
				// exlcude

				config.add_string( "policy-list-exclude",
					i->text( 0 ).toAscii(),
					i->text( 0 ).length() );
			}
		}
	}

	return true;
}

bool _qikeaSite::verify()
{
	QString errmsg;

	// check remote host

	if( lineEditHost->text().length() < 1 )
		errmsg = "Please enter a valid host name or ip address.";

	// local adapter mode

	QString amode = comboBoxAddressMethod->currentText();

	if( !amode.compare( AMTXT_VIRTUAL ) || !amode.compare( AMTXT_RANDOM ) )
	{
		// adapter mtu

		if( ( lineEditMTU->text().toLong() < 68 ) ||
		    ( lineEditMTU->text().toLong() > 1500 ) )
			errmsg = "Please enter valid Adapter MTU from 68 to 1500 bytes.";

		// adapter address

		if( !checkBoxAddressAuto->isChecked() )
		{
			// adapter address

			QString Address = lineEditAddress->text();
			Address = Address.replace( ' ', "" );
			uint32_t addr = inet_addr( Address.toAscii() );

			if( !addr || ( addr == INADDR_NONE ) )
				errmsg = "Please enter valid virtual adapter address.";

			// adapter netmask

			QString Netmask = lineEditNetmask->text();
			Netmask = Netmask.replace( ' ', "" );
			uint32_t mask = inet_addr( Netmask.toAscii() );

			if( !mask )
				errmsg = "Please enter valid virtual adapter netmask.";
		}
	}

	// dns enabled

	if( checkBoxDNSEnable->isChecked() )
	{
		// dns settings

		if( !checkBoxDNSAuto->isChecked() )
		{
			// manual dns server addresses

			QString DNSServer;
			uint32_t addr;

			DNSServer = lineEditDNSServer1->text();
			DNSServer = DNSServer.replace( ' ', "" );
			addr = inet_addr( DNSServer.toAscii() );

			if( addr && ( addr == INADDR_NONE ) )
				errmsg = "Please enter valid DNS server #1 address.";

			DNSServer = lineEditDNSServer2->text();
			DNSServer = DNSServer.replace( ' ', "" );

			if( addr && ( addr == INADDR_NONE ) )
				errmsg = "Please enter valid DNS server #2 address.";

			DNSServer = lineEditDNSServer3->text();
			DNSServer = DNSServer.replace( ' ', "" );

			if( addr && ( addr == INADDR_NONE ) )
				errmsg = "Please enter valid DNS server #3 address.";

			DNSServer = lineEditDNSServer4->text();
			DNSServer = DNSServer.replace( ' ', "" );

			if( addr && ( addr == INADDR_NONE ) )
				errmsg = "Please enter valid DNS server #4 address.";
		}

		if( !checkBoxSuffixAuto->isChecked() )
		{
			// manual dns domain suffix

			QString DNSSuffix = lineEditDNSSuffix->text();

			if( !DNSSuffix.length() )
				errmsg = "Please enter valid DNS suffix.";
		}
	}

	// check local id data

	bool isaddr_l = ( comboBoxLocalIDType->currentText().compare( IDTXT_ADDR ) == 0 );

	if( isaddr_l && lineEditLocalIDData->isEnabled() )
		if( lineEditLocalIDData->text().length() < 1 )
			errmsg = "Please enter valid local ID address data.";

	// check remote id data

	bool isaddr_r = ( comboBoxRemoteIDType->currentText().compare( IDTXT_ADDR ) == 0 );

	if( isaddr_r && lineEditRemoteIDData->isEnabled() )
		if( lineEditRemoteIDData->text().length() < 1 )
			errmsg = "Please enter valid remote ID address data.";

	// check cert authority file

	if( toolButtonCAFile->isEnabled() )
		if( lineEditCAName->text().length() < 1 )
			errmsg = "Please enter valid certificate authority file path.";

	// check cert file

	if( toolButtonCertFile->isEnabled() )
		if( lineEditCertName->text().length() < 1 )
			errmsg = "Please enter valid certificate file path.";

	// check private key file

	if( toolButtonPKeyFile->isEnabled() )
		if( lineEditPKeyName->text().length() < 1 )
			errmsg = "Please enter valid private key file path.";

	// check pre shared key

	if( lineEditPSK->isEnabled() )
		if( lineEditPSK->text().length() < 1 )
			errmsg = "Please enter valid pre-shared key.";

	// verify policy list
/*
	if( !checkBoxPolicyAuto->isChecked() )
		if( !treeWidgetPolicies->childCount() )
			errmsg = "You must specify at least one remote network resource.";
*/

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

	if( comboBoxP1Exchange->currentIndex() == EXCH_MAIN_MODE )
	{
		if( !isaddr_l || !isaddr_r )
		{
			long index = comboBoxAuthMethod->currentIndex();

			if( ( index == AUTH_MUTUAL_PSK_XAUTH ) ||
				( index == AUTH_MUTUAL_PSK ) )
			{
				QMessageBox m;

				m.warning( this,
					"Site Configuration Warning",
					"Main mode and Pre-Shared Keys should be used with Address "
					"ID types. While some gateways require alternate ID types, "
					"use them with caution.",
					QMessageBox::Ok,
					QMessageBox::NoButton,
					QMessageBox::NoButton );
			}
		}
	}
	

	// accept the dialog changes

	accept();

	return true;
}

void _qikeaSite::updateConfigMethod()
{
	updateGeneral( true, true );
}


void _qikeaSite::updateAddressMethod()
{
	updateGeneral( false, true );
}

void _qikeaSite::updateAddressAuto()
{
	updateGeneral( false, false );
}

void _qikeaSite::updateGeneral( bool adflt, bool mdflt )
{
	QString amode = comboBoxAddressMethod->currentText();

	// auto configuration

	long aconf = comboBoxConfigMethod->currentIndex();

	switch( aconf )
	{
		case 0:	// disabled
			comboBoxAddressMethod->setEnabled( true );
			comboBoxAddressMethod->clear();
			comboBoxAddressMethod->addItem( QString( AMTXT_VIRTUAL ) );
			comboBoxAddressMethod->addItem( AMTXT_RANDOM );
			comboBoxAddressMethod->addItem( AMTXT_DIRECT );
			break;

		case 3: // dhcp over ipsec
			comboBoxAddressMethod->setEnabled( true );
			comboBoxAddressMethod->clear();
			comboBoxAddressMethod->addItem( AMTXT_VIRTUAL );
			break;

		default: // push or pull
			comboBoxAddressMethod->setEnabled( true );
			comboBoxAddressMethod->clear();
			comboBoxAddressMethod->addItem( AMTXT_VIRTUAL );
			comboBoxAddressMethod->addItem( AMTXT_DIRECT );
			break;
	}

	combobox_setbytext( amode, comboBoxAddressMethod );

	if( amode != comboBoxAddressMethod->currentText() )
		mdflt = true;

	// adapter mode

	if( !amode.compare( AMTXT_VIRTUAL ) || !amode.compare( AMTXT_RANDOM ) )
	{
		switch( aconf )
		{
			case 0:	// autoconf disabled
				checkBoxAddressAuto->setEnabled( false );
				checkBoxAddressAuto->setChecked( false );
				if( mdflt )
				{
					if( !amode.compare( AMTXT_VIRTUAL ) )
					{
						lineEditAddress->setText( "0.0.0.0" );
						lineEditNetmask->setText( "255.255.255.0" );
					}
				
					if( !amode.compare( AMTXT_RANDOM ) )
					{
						lineEditAddress->setText( "198.18.0.0" );
						lineEditNetmask->setText( "255.254.0.0" );
					}
				}
				break;

			case 1: // ike config push
			case 2: // ike config pull
				checkBoxAddressAuto->setEnabled( true );
				if( mdflt )
				{
					checkBoxAddressAuto->setChecked( true );
					lineEditAddress->setText( "0.0.0.0" );
					lineEditNetmask->setText( "255.255.255.0" );
				}
				break;

			case 3:	// dhcp over ipsec
				checkBoxAddressAuto->setEnabled( false );
				checkBoxAddressAuto->setChecked( true );
				if( mdflt )
				{
					lineEditAddress->setText( "0.0.0.0" );
					lineEditNetmask->setText( "0.0.0.0" );
				}
				break;
		}

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

	updateClient();
	updateNameResolution();
}

void _qikeaSite::updateClient()
{
	long aconf = comboBoxConfigMethod->currentIndex();

	// nat traversal mode

	if( !comboBoxNATTMode->currentIndex() )
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

	if( !comboBoxFragMode->currentIndex() )
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

	// login banner

	if( aconf == 0 )
	{
		checkBoxBanner->setEnabled( false );
		checkBoxBanner->setChecked( false );
	}
	else
		checkBoxBanner->setEnabled( true );
}

void _qikeaSite::updateNameResolution()
{
	long aconf = comboBoxConfigMethod->currentIndex();

	// dns enabled

	if( checkBoxDNSEnable->isChecked() )
	{
		// enabled

		if( aconf == 0 )
		{
			checkBoxDNSAuto->setEnabled( false );
			checkBoxDNSAuto->setChecked( false );

			checkBoxSuffixAuto->setEnabled( false );
			checkBoxSuffixAuto->setChecked( false );
		}
		else
		{
			checkBoxDNSAuto->setEnabled( true );
			checkBoxSuffixAuto->setEnabled( true );
		}

		textLabelDNSServer1->setEnabled( true );
		textLabelDNSServer2->setEnabled( true );
		textLabelDNSServer3->setEnabled( true );
		textLabelDNSServer4->setEnabled( true );

		if( checkBoxDNSAuto->isChecked() )
		{
			lineEditDNSServer1->setEnabled( false );
			lineEditDNSServer2->setEnabled( false );
			lineEditDNSServer3->setEnabled( false );
			lineEditDNSServer4->setEnabled( false );
		}
		else
		{
			lineEditDNSServer1->setEnabled( true );
			lineEditDNSServer2->setEnabled( true );
			lineEditDNSServer3->setEnabled( true );
			lineEditDNSServer4->setEnabled( true );
		}

		textLabelDNSSuffix->setEnabled( true );

		if( checkBoxSuffixAuto->isChecked() )
			lineEditDNSSuffix->setEnabled( false );
		else
			lineEditDNSSuffix->setEnabled( true );
	}
	else
	{
		// disabled

		checkBoxDNSAuto->setEnabled( false );

		textLabelDNSServer1->setEnabled( false );
		textLabelDNSServer2->setEnabled( false );
		textLabelDNSServer3->setEnabled( false );
		textLabelDNSServer4->setEnabled( false );

		lineEditDNSServer1->setEnabled( false );
		lineEditDNSServer2->setEnabled( false );
		lineEditDNSServer3->setEnabled( false );
		lineEditDNSServer4->setEnabled( false );

		checkBoxSuffixAuto->setEnabled( false );

		textLabelDNSSuffix->setEnabled( false );
		lineEditDNSSuffix->setEnabled( false );
	}
}

void _qikeaSite::updateAuthMethod()
{
	// authentication method

	long auth = comboBoxAuthMethod->currentIndex();

	switch( auth )
	{
		case AUTH_HYBRID_RSA_XAUTH:
		case AUTH_HYBRID_GRP_XAUTH:
		{
			comboBoxLocalIDType->clear();

//			comboBoxLocalIDType->addItem( IDTXT_NONE );
			comboBoxLocalIDType->addItem( IDTXT_FQDN );
			comboBoxLocalIDType->addItem( IDTXT_UFQDN );
			comboBoxLocalIDType->addItem( IDTXT_ADDR );
			comboBoxLocalIDType->addItem( IDTXT_KEYID );

			break;
		}

		case AUTH_MUTUAL_RSA_XAUTH:
		case AUTH_MUTUAL_RSA:
		{
			comboBoxLocalIDType->clear();

			comboBoxLocalIDType->addItem( IDTXT_ASN1 );
			comboBoxLocalIDType->addItem( IDTXT_FQDN );
			comboBoxLocalIDType->addItem( IDTXT_UFQDN );
			comboBoxLocalIDType->addItem( IDTXT_ADDR );
			comboBoxLocalIDType->addItem( IDTXT_KEYID );

			break;
		}

		case AUTH_MUTUAL_PSK_XAUTH:
		case AUTH_MUTUAL_PSK:
		{
			comboBoxLocalIDType->clear();

			comboBoxLocalIDType->addItem( IDTXT_FQDN );
			comboBoxLocalIDType->addItem( IDTXT_UFQDN );
			comboBoxLocalIDType->addItem( IDTXT_ADDR );
			comboBoxLocalIDType->addItem( IDTXT_KEYID );

			break;
		}
	}

	switch( auth )
	{
		case AUTH_HYBRID_RSA_XAUTH:
		case AUTH_HYBRID_GRP_XAUTH:
		case AUTH_MUTUAL_RSA_XAUTH:
		case AUTH_MUTUAL_RSA:
		{
			comboBoxRemoteIDType->clear();

			comboBoxRemoteIDType->addItem( IDTXT_ANY );
			comboBoxRemoteIDType->addItem( IDTXT_ASN1 );
			comboBoxRemoteIDType->addItem( IDTXT_FQDN );
			comboBoxRemoteIDType->addItem( IDTXT_UFQDN );
			comboBoxRemoteIDType->addItem( IDTXT_ADDR );
			comboBoxRemoteIDType->addItem( IDTXT_KEYID );

			break;
		}

		case AUTH_MUTUAL_PSK_XAUTH:
		case AUTH_MUTUAL_PSK:
		{
			comboBoxRemoteIDType->clear();

			comboBoxRemoteIDType->addItem( IDTXT_ANY );
			comboBoxRemoteIDType->addItem( IDTXT_FQDN );
			comboBoxRemoteIDType->addItem( IDTXT_UFQDN );
			comboBoxRemoteIDType->addItem( IDTXT_ADDR );
			comboBoxRemoteIDType->addItem( IDTXT_KEYID );

			break;
		}
	}
}

void _qikeaSite::updateAuthentication()
{
	// grab the current local and remote id types

	QString locid = comboBoxLocalIDType->currentText();
	QString rmtid = comboBoxRemoteIDType->currentText();

	// update the authentication method

	updateAuthMethod();

	// attempt to re-select the id types

	if( !combobox_setbytext( locid, comboBoxLocalIDType ) )
	{
		lineEditLocalIDData->clear();
		checkBoxLocalIDOption->setChecked( true );
	}

	if( !combobox_setbytext( rmtid, comboBoxRemoteIDType ) )
	{
		lineEditRemoteIDData->clear();
		checkBoxRemoteIDOption->setChecked( true );
	}

	// authentication credentials

	switch( comboBoxAuthMethod->currentIndex() )
	{
		case AUTH_HYBRID_RSA_XAUTH:
		{
			lineEditCAName->setEnabled( true );
			toolButtonCAFile->setEnabled( true );
			lineEditCertName->setEnabled( false );
			toolButtonCertFile->setEnabled( false );
			lineEditPKeyName->setEnabled( false );
			toolButtonPKeyFile->setEnabled( false );
			lineEditPSK->setEnabled( false );

			break;
		}

		case AUTH_HYBRID_GRP_XAUTH:
		{
			lineEditCAName->setEnabled( true );
			toolButtonCAFile->setEnabled( true );
			lineEditCertName->setEnabled( false );
			toolButtonCertFile->setEnabled( false );
			lineEditPKeyName->setEnabled( false );
			toolButtonPKeyFile->setEnabled( false );
			lineEditPSK->setEnabled( true );

			break;
		}

		case AUTH_MUTUAL_RSA_XAUTH:
		case AUTH_MUTUAL_RSA:
		{
			lineEditCAName->setEnabled( true );
			toolButtonCAFile->setEnabled( true );
			lineEditCertName->setEnabled( true );
			toolButtonCertFile->setEnabled( true );
			lineEditPKeyName->setEnabled( true );
			toolButtonPKeyFile->setEnabled( true );
			lineEditPSK->setEnabled( false );

			break;
		}

		case AUTH_MUTUAL_PSK_XAUTH:
		case AUTH_MUTUAL_PSK:
		{
			lineEditCAName->setEnabled( false );
			toolButtonCAFile->setEnabled( false );
			lineEditCertName->setEnabled( false );
			toolButtonCertFile->setEnabled( false );
			lineEditPKeyName->setEnabled( false );
			toolButtonPKeyFile->setEnabled( false );
			lineEditPSK->setEnabled( true );

			break;
		}
	}

	updateLocalID();
	updateRemoteID();
}

void _qikeaSite::updateLocalID()
{
	QString type = comboBoxLocalIDType->currentText();

	if( !type.compare( IDTXT_NONE ) )
	{
		textLabelLocalIDData->setText( "" );
		lineEditLocalIDData->setEnabled( false );
		checkBoxLocalIDOption->setHidden( true );
		return;
	}

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

void _qikeaSite::updateRemoteID()
{
	QString type = comboBoxRemoteIDType->currentText();

	if( !type.compare( IDTXT_ANY ) )
	{
		textLabelRemoteIDData->setText( "" );
		lineEditRemoteIDData->setEnabled( false );
		checkBoxRemoteIDOption->setHidden( true );
		return;
	}

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

void _qikeaSite::updatePhase1()
{
	// exchange mode

	if( comboBoxP1Exchange->currentIndex() == EXCH_AGGR_MODE )
	{
		// aggressive mode ( auto not allowed )

		QString text = comboBoxP1DHGroup->currentText();

		comboBoxP1DHGroup->clear();
		comboBoxP1DHGroup->addItem( "group 1" );
		comboBoxP1DHGroup->addItem( "group 2" );
		comboBoxP1DHGroup->addItem( "group 5" );
		comboBoxP1DHGroup->addItem( "group 14" );
		comboBoxP1DHGroup->addItem( "group 15" );

		combobox_setbytext( text, comboBoxP1DHGroup );
	}

	if( comboBoxP1Exchange->currentIndex() == EXCH_MAIN_MODE )
	{
		// main mode ( auto allowed )

		QString text = comboBoxP1DHGroup->currentText();

		comboBoxP1DHGroup->clear();
		comboBoxP1DHGroup->addItem( "auto" );
		comboBoxP1DHGroup->addItem( "group 1" );
		comboBoxP1DHGroup->addItem( "group 2" );
		comboBoxP1DHGroup->addItem( "group 5" );
		comboBoxP1DHGroup->addItem( "group 14" );
		comboBoxP1DHGroup->addItem( "group 15" );

		combobox_setbytext( text, comboBoxP1DHGroup );
	}

	// chipher type

	QString text = comboBoxP1Keylen->currentText();

	switch( comboBoxP1Cipher->currentIndex() )
	{
		case 1: // aes
		{
			comboBoxP1Keylen->setEnabled( true );
			comboBoxP1Keylen->clear();
			comboBoxP1Keylen->addItem( "auto" );
			comboBoxP1Keylen->addItem( "128" );
			comboBoxP1Keylen->addItem( "192" );
			comboBoxP1Keylen->addItem( "256" );
			break;
		}

		case 2: // blowfish
		{
			comboBoxP1Keylen->setEnabled( true );
			comboBoxP1Keylen->clear();
			comboBoxP1Keylen->addItem( "auto" );
			for( long b = 128; b <= 256; b += 8 )
				comboBoxP1Keylen->addItem(
					QString::number( b, 10 ) );
			break;
		}

		default: // all others
		{
			comboBoxP1Keylen->setCurrentIndex( 0 );
			comboBoxP1Keylen->setEnabled( false );
			break;
		}
	}

	if( !comboBoxP1Cipher->currentIndex() )
		comboBoxP1Keylen->setCurrentIndex( 0 );
	else
		combobox_setbytext( text, comboBoxP1Keylen );

	updateAuthentication();
}

void _qikeaSite::updatePhase2()
{
	// transform type

	QString text = comboBoxP2Keylen->currentText();

	switch( comboBoxP2Transform->currentIndex() )
	{
		case 1: // aes
		{
			comboBoxP2Keylen->setEnabled( true );
			comboBoxP2Keylen->clear();
			comboBoxP2Keylen->addItem( "auto" );
			comboBoxP2Keylen->addItem( "128" );
			comboBoxP2Keylen->addItem( "192" );
			comboBoxP2Keylen->addItem( "256" );
			break;
		}

		case 2: // blowfish
		{
			comboBoxP2Keylen->setEnabled( true );
			comboBoxP2Keylen->clear();
			comboBoxP2Keylen->addItem( "auto" );
			for( long b = 128; b <= 256; b += 8 )
				comboBoxP2Keylen->addItem(
					QString::number( b, 10 ) );
			break;
		}

		default: // all others
		{
			comboBoxP2Keylen->setCurrentIndex( 0 );
			comboBoxP2Keylen->setEnabled( false );
			break;
		}
	}

	if( !comboBoxP2Transform->currentIndex() )
		comboBoxP2Keylen->setCurrentIndex( 0 );
	else
		combobox_setbytext( text, comboBoxP2Keylen );
}

void _qikeaSite::updatePolicy()
{
	// policy configuration

	if( checkBoxPolicyAuto->isChecked() )
	{
		// automatic

		treeWidgetPolicies->setEnabled( false );

		pushButtonPolicyAdd->setEnabled( false );
		pushButtonPolicyMod->setEnabled( false );
		pushButtonPolicyDel->setEnabled( false );
	}
	else
	{
		// manual

		treeWidgetPolicies->setEnabled( true );

		pushButtonPolicyAdd->setEnabled( true );

		// policy item selection

		if( treeWidgetPolicies->currentItem() != NULL )
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

void _qikeaSite::selectLocalID()
{                        
	lineEditLocalIDData->clear();
	checkBoxLocalIDOption->setChecked( true );

	updateLocalID();
}

void _qikeaSite::selectRemoteID()
{
	lineEditRemoteIDData->clear();
	checkBoxRemoteIDOption->setChecked( true );

	updateRemoteID();
}

void _qikeaSite::inputCAFile()
{
	QString types(
		"OpenSSL Files (*.key *.pem *.crt *.crt);;"
		"PKCS #12 Files (*.p12 *.pfx);;"
		"All files (*)" );

	QString filePath = QFileDialog::getOpenFileName(
				this, "Select CA File",
				QDir::homePath(),
				types );

	if( filePath.length() )
	{
		pathCAFile = filePath;
		QFileInfo fileInfo( filePath );
		lineEditCAName->setText( fileInfo.fileName() );
	}
}

void _qikeaSite::inputCertFile()
{
	QString types(
		"OpenSSL Files (*.key *.pem *.crt *.crt);;"
		"PKCS #12 Files (*.p12 *.pfx);;"
		"All files (*)" );

	QString filePath = QFileDialog::getOpenFileName(
				this, "Select CA File",
				QDir::homePath(),
				types );

	if( filePath.length() )
	{
		pathCertFile = filePath;
		QFileInfo fileInfo( filePath );
		lineEditCertName->setText( fileInfo.fileName() );
	}
}


void _qikeaSite::inputPKeyFile()
{
	QString types(
		"OpenSSL Files (*.key *.pem *.crt *.crt);;"
		"PKCS #12 Files (*.p12 *.pfx);;"
		"All files (*)" );

	QString filePath = QFileDialog::getOpenFileName(
				this, "Select CA File",
				QDir::homePath(),
				types );

	if( filePath.length() )
	{
		pathPKeyFile = filePath;
		QFileInfo fileInfo( filePath );
		lineEditPKeyName->setText( fileInfo.fileName() );
	}
}
