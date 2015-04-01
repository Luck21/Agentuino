/*
  Agentuino.cpp - An Arduino library for a lightweight SNMP Agent.
  Copyright (C) 2010 Eric C. Gionet <lavco_eg@hotmail.com>
  All rights reserved.
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.
  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.
  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

//
// sketch_aug23a
//

#include "Agentuino.h"
#include <avr/pgmspace.h>
#include <Ethernet.h>
#include <EthernetUdp.h>

EthernetUDP Udp;
SNMP_API_STAT_CODES AgentuinoClass::begin()
{
	// set community names
	_getCommName = "public";
	_setCommName = "private";
	_trapCommName = "public";
	//
	// set community name set/get sizes
	_setSize = strlen(_setCommName);
	_getSize = strlen(_getCommName);
	_trapSize = strlen(_trapCommName);
	//
	// init UDP socket
	Udp.begin(SNMP_DEFAULT_PORT);
	//

	trapNum = -1;

	return SNMP_API_STAT_SUCCESS;
}

SNMP_API_STAT_CODES AgentuinoClass::begin(char *getCommName,
        char *setCommName, char *trapCommName, uint16_t port)
{
	// set community name set/get sizes
	_setSize = strlen(setCommName);
	_getSize = strlen(getCommName);
	_trapSize = strlen(trapCommName);
	//
	// validate get/set community name sizes
	if ( _setSize > SNMP_MAX_NAME_LEN + 1 || _getSize > SNMP_MAX_NAME_LEN + 1 ) {
		return SNMP_API_STAT_NAME_TOO_BIG;
	}
	//
	// set community names
	_getCommName = getCommName;
	_setCommName = setCommName;
	//
	// validate session port number
	if ( port == NULL || port == 0 ) port = SNMP_DEFAULT_PORT;
	//
	// init UDP socket
	Udp.begin(port);

	return SNMP_API_STAT_SUCCESS;
}

void AgentuinoClass::listen(void)
{
	time_ticks = millis()/10;

	// if bytes are available in receive buffer
	// and pointer to a function (delegate function)
	// isn't null, trigger the function
	Udp.parsePacket();
	if ( Udp.available() && _callback != NULL ) (*_callback)();
}

SNMP_API_STAT_CODES AgentuinoClass::mountTrapPdu(TRAP *trap, SNMP_PDU *pdu)
{
	
	/*uint32_u *ip = (uint32_u *) malloc(sizeof(uint32_u));
	
	if(ip == null)
		return snmp_api_stat_malloc_err;
	
	pdu->address = ip->data;

	free(ip);*/
	uint32_u ip;
	uint8_t listSize = 0;
	VAR_BIND_LIST *tmpList = (VAR_BIND_LIST *) malloc(sizeof(VAR_BIND_LIST));
	
	if(tmpList == NULL)
		return SNMP_API_STAT_MALLOC_ERR;

	tmpList = trap->varBindList;

	ip.uint32 = Ethernet.localIP();
	
	pdu->address = ip.data;
  	pdu->type = SNMP_PDU_TRAP;
  	pdu->OID.fromString(trap->oid);
  	pdu->trap_type = trap->trapType;//SNMP_TRAP_WARM_START;
  	pdu->specific_trap = trap->specificTrap;
  	pdu->time_ticks = time_ticks;
	pdu->trap_data_size = 0;
	pdu->trap_data = NULL;

	//found the size of varBindList
	while(tmpList != NULL)
	{
		listSize++;//type
		listSize++;//length
		if(tmpList->type == SNMP_SYNTAX_COUNTER64)
			listSize += 8;
		else if(tmpList->type == SNMP_SYNTAX_OCTETS)
			listSize += strlen((char *)tmpList->var);
		else
			listSize += 4;
		tmpList = tmpList->nextVar;
	}
	
	free(tmpList);
	
  	pdu->trap_data_size = listSize;
	
	if(listSize)
		//allocate trap data
		pdu->trap_data = (byte *) malloc(sizeof(byte)*listSize);
	else
		Serial.println("\n Varbind is NULL");
	
	if(pdu->trap_data == NULL && listSize != 0)
		return SNMP_API_STAT_MALLOC_ERR;
	else
	{
		uint8_t j = 0;
		while(trap->varBindList != NULL)
		{
			byte k = 0;
			
			pdu->trap_data[j++] = trap->varBindList->type;
			
			if(trap->objType == SNMP_SYNTAX_COUNTER64)
				k = 8;
			else if(trap->objType == SNMP_SYNTAX_OCTETS)
				k = strlen((char *)trap->varBindList->var);
			else
				k = 4;

			pdu->trap_data[j++] = k;

			memcpy(pdu->trap_data + j, trap->varBindList->var, k);

			trap->varBindList = trap->varBindList->nextVar;
		}

	}

  	/* the function that adds this data */
  	//pdu->trap_data_adder = add_trap_data;
	Serial.println(F("Sending TRAP"));
	const uint8_t manager[] = {192, 168, 0, 110};

  	Agentuino.sendTrap(pdu, manager);
}

SNMP_API_STAT_CODES AgentuinoClass::requestPdu(SNMP_PDU *pdu)
{
	char *community;
	// sequence length
	byte seqLen;
	// version
	byte verLen, verEnd;
	// community string
	byte comLen, comEnd;
	// pdu
	byte pduTyp, pduLen;
	byte ridLen, ridEnd;
	byte errLen, errEnd;
	byte eriLen, eriEnd;
	byte vblTyp, vblLen;
	byte vbiTyp, vbiLen;
	byte obiLen, obiEnd;
	byte valTyp, valLen, valEnd;
	byte i;
	//
	// set packet packet size (skip UDP header)
	_packetSize = Udp.available();
	//
	// reset packet array
	memset(_packet, 0, SNMP_MAX_PACKET_LEN);
	//
	// validate packet
	if ( _packetSize != 0 && _packetSize > SNMP_MAX_PACKET_LEN ) {
		//
		//SNMP_FREE(_packet);

		return SNMP_API_STAT_PACKET_TOO_BIG;
	}
	//
	// get UDP packet
	//Udp.parsePacket();
	Udp.read(_packet, _packetSize);
// 	Udp.readPacket(_packet, _packetSize, _dstIp, &_dstPort);
	//
	// packet check 1
	if ( _packet[0] != 0x30 ) {
		//
		//SNMP_FREE(_packet);

		return SNMP_API_STAT_PACKET_INVALID;
	}
	//
	// sequence length
	seqLen = _packet[1];
	// version
	verLen = _packet[3];
	verEnd = 3 + verLen;
	// community string
	comLen = _packet[verEnd + 2];
	comEnd = verEnd + 2 + comLen;
	// pdu
	pduTyp = _packet[comEnd + 1];
	pduLen = _packet[comEnd + 2];
	ridLen = _packet[comEnd + 4];
	ridEnd = comEnd + 4 + ridLen;
	errLen = _packet[ridEnd + 2];
	errEnd = ridEnd + 2 + errLen;
	eriLen = _packet[errEnd + 2];
	eriEnd = errEnd + 2 + eriLen;
	vblTyp = _packet[eriEnd + 1];
	vblLen = _packet[eriEnd + 2];
	vbiTyp = _packet[eriEnd + 3];
	vbiLen = _packet[eriEnd + 4];
	obiLen = _packet[eriEnd + 6];
	obiEnd = eriEnd + obiLen + 6;
	valTyp = _packet[obiEnd + 1];
	valLen = _packet[obiEnd + 2];
	valEnd = obiEnd + 2 + valLen;
	//
	// extract version
	pdu->version = 0;
	for ( i = 0; i < verLen; i++ ) {
		pdu->version = (pdu->version << 8) | _packet[5 + i];
	}
	//
	// validate version
	//
	// pdu-type
	pdu->type = (SNMP_PDU_TYPES)pduTyp;
	_dstType = pdu->type;
	//
	// validate community size
	if ( comLen > SNMP_MAX_NAME_LEN ) {
		// set pdu error
		pdu->error = SNMP_ERR_TOO_BIG;
		//
		return SNMP_API_STAT_NAME_TOO_BIG;
	}
	//
	//
	// validate community name
	if ( pdu->type == SNMP_PDU_SET && comLen == _setSize ) {
		//
		for ( i = 0; i < _setSize; i++ ) {
			if( _packet[verEnd + 3 + i] != (byte)_setCommName[i] ) {
				// set pdu error
				pdu->error = SNMP_ERR_NO_SUCH_NAME;
				//
				return SNMP_API_STAT_NO_SUCH_NAME;
			}
		}
	} else if ( pdu->type == SNMP_PDU_GET && comLen == _getSize ) {
		//
		for ( i = 0; i < _getSize; i++ ) {
			if( _packet[verEnd + 3 + i] != (byte)_getCommName[i] ) {
				// set pdu error
				pdu->error = SNMP_ERR_NO_SUCH_NAME;
				//
				return SNMP_API_STAT_NO_SUCH_NAME;
			}
		}
	} else if ( pdu->type == SNMP_PDU_GET_NEXT && comLen == _getSize ) {
		//
		for ( i = 0; i < _getSize; i++ ) {
			if( _packet[verEnd + 3 + i] != (byte)_getCommName[i] ) {
				// set pdu error
				pdu->error = SNMP_ERR_NO_SUCH_NAME;
				//
				return SNMP_API_STAT_NO_SUCH_NAME;
			}
		}
	} else {
		// set pdu error
		pdu->error = SNMP_ERR_NO_SUCH_NAME;
		//
		return SNMP_API_STAT_NO_SUCH_NAME;
	}
	//
	//
	// extract reqiest-id 0x00 0x00 0x00 0x01 (4-byte int aka int32)
	pdu->requestId = 0;
	for ( i = 0; i < ridLen; i++ ) {
		pdu->requestId = (pdu->requestId << 8) | _packet[comEnd + 5 + i];
	}
	//
	// extract error 
	pdu->error = SNMP_ERR_NO_ERROR;
	int32_t err = 0;
	for ( i = 0; i < errLen; i++ ) {
		err = (err << 8) | _packet[ridEnd + 3 + i];
	}
	pdu->error = (SNMP_ERR_CODES)err;
	//
	// extract error-index 
	pdu->errorIndex = 0;
	for ( i = 0; i < eriLen; i++ ) {
		pdu->errorIndex = (pdu->errorIndex << 8) | _packet[errEnd + 3 + i];
	}
	//
	//
	// validate object-identifier size
	if ( obiLen > SNMP_MAX_OID_LEN ) {
		// set pdu error
		pdu->error = SNMP_ERR_TOO_BIG;

		return SNMP_API_STAT_OID_TOO_BIG;
	}
	//
	// extract and contruct object-identifier
	memset(pdu->OID.data, 0, SNMP_MAX_OID_LEN);
	pdu->OID.size = obiLen;
	for ( i = 0; i < obiLen; i++ ) {
		pdu->OID.data[i] = _packet[eriEnd + 7 + i];
	}
	//
	// value-type
	pdu->VALUE.syntax = (SNMP_SYNTAXES)valTyp;
	//
	// validate value size
	if ( obiLen > SNMP_MAX_VALUE_LEN ) {
		// set pdu error
		pdu->error = SNMP_ERR_TOO_BIG;

		return SNMP_API_STAT_VALUE_TOO_BIG;
	}
	//
	// value-size
	pdu->VALUE.size = valLen;
	//
	// extract value
	memset(pdu->VALUE.data, 0, SNMP_MAX_VALUE_LEN);
	for ( i = 0; i < valLen; i++ ) {
		pdu->VALUE.data[i] = _packet[obiEnd + 3 + i];
	}
	//
	return SNMP_API_STAT_SUCCESS;
}

/*
 * installTrap
 * notice a Trap condition to API.
 * const char *oid - the OID 
 *
*/
uint8_t AgentuinoClass::installTrap (const char *oid, SNMP_TRAP_TYPES trapType, 
				     void *obj, SNMP_SYNTAXES objType, 
 				     enum relational_op rel_op, void *base_measure,
				     VAR_BIND_LIST *varBindList)
{
	if(trapNum >= MAX_TRAPS)
	{
		Serial.println(F("\n\rerror installTrap(): trap_list is FULL!\n\r"));
		return 1; //error
	}

	trap_list[++trapNum].objType = objType;
	trap_list[trapNum].trapType = trapType;
	strcpy_P(trap_list[trapNum].oid, (PGM_P) oid);
	//Serial.println(trap_list[trapNum].oid);	//debug
	//Serial.println(trap_list[trapNum].oid);
	trap_list[trapNum].object_var = obj;
	trap_list[trapNum].condition  = rel_op;
	trap_list[trapNum].base_measure = base_measure;
	trap_list[trapNum].send = false;
	trap_list[trapNum].varBindList = varBindList;
	
	return 0;
}


/*
 * This function check if some condition in "trap_list" has been achieved. 
 * uint8_t trapWatcher (void)
 *	params: void
 *	return: 255 if trap_list is null, otherwise return Number of conditions traps achieved.
*/
uint8_t AgentuinoClass::trapWatcher(void)
{
	uint8_t achievedTraps = 0;

	//table_rel: basic relational operations
	//----------------------------------------------------
	//bit| 7 | 6 |   5  |  4  |   3  |   2  |   1  |  0  |
	//====================================================
	//val| 1 | 1 | a!=b | a==b | a>=b | a>b | a<=b | a<b |
	//----------------------------------------------------
	uint8_t table_rel;// = 0b11000000;

	if(trapNum < 0)
		return 255;

	for(uint8_t i = 0; i <= trapNum; i++)
	{
		table_rel = 0b11000000;

		switch(trap_list[i].objType)
		{
			case(SNMP_SYNTAX_UINT32):
			case(SNMP_SYNTAX_INT):
			case(SNMP_SYNTAX_COUNTER):
			case(SNMP_SYNTAX_GAUGE):
			case(SNMP_SYNTAX_TIME_TICKS):
			{	
				uint32_t a = *((uint32_t *) trap_list[i].object_var);
				uint32_t b = *((uint32_t *) trap_list[i].base_measure);
				
				table_rel |= ((a!=b)<<NOT_EQUAL);
				table_rel |= ((a==b)<<EQUAL);
				table_rel |= ((a>=b)<<GREATER_OR_EQUAL);
				table_rel |= ((a>b)<<GREATER_THAN);
				table_rel |= ((a<=b)<<LESS_OR_EQUAL);
				table_rel += (a<b);
			}
			break;
			case(SNMP_SYNTAX_COUNTER64):
			{
				uint64_t a = *((uint64_t *) trap_list[i].object_var);
				uint64_t b = *((uint64_t *) trap_list[i].base_measure);
				
				table_rel |= ((a!=b)<<NOT_EQUAL);
				table_rel |= ((a==b)<<EQUAL);
				table_rel |= ((a>=b)<<GREATER_OR_EQUAL);
				table_rel |= ((a>b)<<GREATER_THAN);
				table_rel |= ((a<=b)<<LESS_OR_EQUAL);
				table_rel += (a<b);
			}
			break;
		}
		
		trap_list[i].send = ((1<<trap_list[i].condition) & table_rel);

		if(trap_list[i].send)
		{
			achievedTraps++;

			/*Serial.print(table_rel, BIN);
			Serial.print(' ');
			Serial.print((1<<trap_list[i].condition) & table_rel, BIN);*/
			Serial.print(F(" trapWatcher(): Sending trap -> "));
			Serial.println(trap_list[i].oid);
			
			SNMP_PDU pdu;

			if(mountTrapPdu(trap_list + i, &pdu))
			{
				Serial.println(F("mountTrapPdu error"));
				return 255;
			}

  		//	pdu.type = SNMP_PDU_TRAP;
  		//	pdu.OID.fromString(trap_list[i].oid);
  		//	pdu.address = agent;
  		//	pdu.trap_type = trap_type;//SNMP_TRAP_WARM_START;
  		//	pdu.specific_trap = 1;
 		//	pdu.time_ticks = time_ticks;

			//future implementation
			/* the size of the data you will add at the end of the packet */
 			//pdu.trap_data_size = 0;
 			/* the function that adds this data */
 			//pdu.trap_data_adder = add_trap_data;

 			//if(Agentuino.sendTrap(&pdu, ) == SNMP_API_STAT_SUCCESS)
			//	trap_list[i].send = false;
		}
	}

	return achievedTraps;
}

SNMP_API_STAT_CODES AgentuinoClass::sendTrap(
        SNMP_PDU *pdu, const uint8_t* manager)
{
	byte i;
    SNMP_VALUE value;
    _dstType = pdu->type = SNMP_PDU_TRAP;
	_packetPos = 0;
    uint16_t size = pdu->OID.size + 27
        + 2 + pdu->trap_data_size;
    writeHeaders(pdu, size);
    _packet[_packetPos++] = (byte) size - 1;
    _packet[_packetPos++] = (byte) SNMP_SYNTAX_OID;
	_packet[_packetPos++] = (byte) (pdu->OID.size);
	for(i = 0; i < pdu->OID.size; i++)
		_packet[_packetPos++] = pdu->OID.data[i];
    _packet[_packetPos++] = (byte) SNMP_SYNTAX_IP_ADDRESS;
    _packet[_packetPos++] = (byte) 4;
    for(i = 0; i < 4; i++) _packet[_packetPos++] = pdu->address[i];
	_packet[_packetPos++] = (byte) SNMP_SYNTAX_INT;
    value.encode(SNMP_SYNTAX_INT, pdu->trap_type);
	_packet[_packetPos++] = (byte) sizeof(pdu->trap_type);
	_packet[_packetPos++] = value.data[0];
	_packet[_packetPos++] = value.data[1];
	_packet[_packetPos++] = (byte) SNMP_SYNTAX_INT;
    value.encode(SNMP_SYNTAX_INT, pdu->specific_trap);
	_packet[_packetPos++] = (byte) sizeof(pdu->specific_trap);
	_packet[_packetPos++] = value.data[0];
	_packet[_packetPos++] = value.data[1];
	_packet[_packetPos++] = (byte) SNMP_SYNTAX_TIME_TICKS;
	_packet[_packetPos++] = (byte) sizeof(pdu->time_ticks);
    value.encode(SNMP_SYNTAX_TIME_TICKS, pdu->time_ticks);
	_packet[_packetPos++] = value.data[0];
	_packet[_packetPos++] = value.data[1];
	_packet[_packetPos++] = value.data[2];
	_packet[_packetPos++] = value.data[3];

	if(pdu->trap_data_size)
	{
    		//_packet[_packetPos++] = (byte) SNMP_SYNTAX_SEQUENCE;
    		//_packet[_packetPos++] = (byte) 4 + pdu->trap_data_size;
    		_packet[_packetPos++] = (byte) SNMP_SYNTAX_SEQUENCE;
    		_packet[_packetPos++] = (byte) pdu->trap_data_size;

		for(i = 0; i < pdu->trap_data_size; i++)
			_packet[_packetPos++] = *(pdu->trap_data + i);
	}

    //pdu->trap_data_adder(_packet + _packetPos);
    return writePacket(manager, 162);
}

void AgentuinoClass::writeHeaders(SNMP_PDU *pdu, uint16_t size)
{
	int32_u u;
	byte i;
	//
	// Length of entire SNMP packet
	_packetPos = 0;  // 23
	_packetSize = 8 + size;
	//
	memset(_packet, 0, SNMP_MAX_PACKET_LEN);
	//
	if ( _dstType == SNMP_PDU_SET ) {
		_packetSize += _setSize;
	} else {
        if ( _dstType == SNMP_PDU_TRAP ) {
            _packetSize += _trapSize;
        } else {
            _packetSize += _getSize;
        }
    }
	//
	_packet[_packetPos++] = (byte)SNMP_SYNTAX_SEQUENCE;	// type
	_packet[_packetPos++] = (byte)_packetSize - 2;		// length
	//
	// SNMP version
	_packet[_packetPos++] = (byte)SNMP_SYNTAX_INT;	// type
	_packet[_packetPos++] = 0x01;			// length
	_packet[_packetPos++] = 0x00;			// value
	//
	// SNMP community string
	_packet[_packetPos++] = (byte)SNMP_SYNTAX_OCTETS;	// type
	if ( _dstType == SNMP_PDU_SET ) {
		_packet[_packetPos++] = (byte)_setSize;	// length
		for ( i = 0; i < _setSize; i++ ) {
			_packet[_packetPos++] = (byte)_setCommName[i];
		}
	} else {
        if ( _dstType == SNMP_PDU_TRAP ) {
            _packet[_packetPos++] = (byte)_trapSize;	// length
            for ( i = 0; i < _getSize; i++ ) {
                _packet[_packetPos++] = (byte)_trapCommName[i];
            }
        } else {
            _packet[_packetPos++] = (byte)_getSize;	// length
            for ( i = 0; i < _getSize; i++ ) {
                _packet[_packetPos++] = (byte)_getCommName[i];
            }
        }
	}
	//
	// SNMP PDU
	_packet[_packetPos++] = (byte)pdu->type;
}

SNMP_API_STAT_CODES AgentuinoClass::responsePdu(SNMP_PDU *pdu)
{
	int32_u u;
	byte i;
    this->writeHeaders(pdu, 17 +
            sizeof(pdu->requestId) + sizeof(pdu->error)
            + sizeof(pdu->errorIndex) + pdu->OID.size
            + pdu->VALUE.size);
	_packet[_packetPos++] = (byte)( sizeof(pdu->requestId) + sizeof((int32_t)pdu->error) + sizeof(pdu->errorIndex) + pdu->OID.size + pdu->VALUE.size + 14 );
	//
	// Request ID (size always 4 e.g. 4-byte int)
	_packet[_packetPos++] = (byte)SNMP_SYNTAX_INT;	// type
	_packet[_packetPos++] = (byte)sizeof(pdu->requestId);
	u.int32 = pdu->requestId;
	_packet[_packetPos++] = u.data[3];
	_packet[_packetPos++] = u.data[2];
	_packet[_packetPos++] = u.data[1];
	_packet[_packetPos++] = u.data[0];
	//
	// Error (size always 4 e.g. 4-byte int)
	_packet[_packetPos++] = (byte)SNMP_SYNTAX_INT;	// type
	_packet[_packetPos++] = (byte)sizeof((int32_t)pdu->error);
	u.int32 = pdu->error;
	_packet[_packetPos++] = u.data[3];
	_packet[_packetPos++] = u.data[2];
	_packet[_packetPos++] = u.data[1];
	_packet[_packetPos++] = u.data[0];
	//
	// Error Index (size always 4 e.g. 4-byte int)
	_packet[_packetPos++] = (byte)SNMP_SYNTAX_INT;	// type
	_packet[_packetPos++] = (byte)sizeof(pdu->errorIndex);
	u.int32 = pdu->errorIndex;
	_packet[_packetPos++] = u.data[3];
	_packet[_packetPos++] = u.data[2];
	_packet[_packetPos++] = u.data[1];
	_packet[_packetPos++] = u.data[0];
	//
	// Varbind List
	_packet[_packetPos++] = (byte)SNMP_SYNTAX_SEQUENCE;	// type
	_packet[_packetPos++] = (byte)( pdu->OID.size + pdu->VALUE.size + 6 ); //4
	//
	// Varbind
	_packet[_packetPos++] = (byte)SNMP_SYNTAX_SEQUENCE;	// type
	_packet[_packetPos++] = (byte)( pdu->OID.size + pdu->VALUE.size + 4 ); //2
	//
	// ObjectIdentifier
	_packet[_packetPos++] = (byte)SNMP_SYNTAX_OID;	// type
	_packet[_packetPos++] = (byte)(pdu->OID.size);
	for ( i = 0; i < pdu->OID.size; i++ ) {
		_packet[_packetPos++] = pdu->OID.data[i];
	}
	//
	// Value
	_packet[_packetPos++] = (byte)pdu->VALUE.syntax;	// type
	_packet[_packetPos++] = (byte)(pdu->VALUE.size);
	for ( i = 0; i < pdu->VALUE.size; i++ ) {
		_packet[_packetPos++] = pdu->VALUE.data[i];
	}
    return writePacket(Udp.remoteIP(), Udp.remotePort());
}

SNMP_API_STAT_CODES AgentuinoClass::writePacket(
        IPAddress address, uint16_t port)
{
	Udp.beginPacket(address, port);
	Udp.write(_packet, _packetSize);
	Udp.endPacket();
	return SNMP_API_STAT_SUCCESS;
}

void AgentuinoClass::onPduReceive(onPduReceiveCallback pduReceived)
{
	_callback = pduReceived;
}

void AgentuinoClass::freePdu(SNMP_PDU *pdu)
{
	//
	memset(pdu->OID.data, 0, SNMP_MAX_OID_LEN);
	memset(pdu->VALUE.data, 0, SNMP_MAX_VALUE_LEN);
	free((char *) pdu);
}

// Create one global object
AgentuinoClass Agentuino;
