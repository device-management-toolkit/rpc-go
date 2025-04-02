/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package pthi

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/open-amt-cloud-toolkit/rpc-go/v2/pkg/heci"
)

type Command struct {
	Heci heci.Interface
}

type Interface interface {
	Open(useLME bool) error
	OpenWatchdog() error
	Close()
	Call(command []byte, commandSize uint32) (result []byte, err error)
	GetCodeVersions() (GetCodeVersionsResponse, error)
	GetUUID() (uuid string, err error)
	GetControlMode() (state int, err error)
	GetIsAMTEnabled() (uint8, error)
	SetAmtOperationalState(state AMTOperationalState) (Status, error)
	GetDNSSuffix() (suffix string, err error)
	GetCertificateHashes(hashHandles AMTHashHandles) (hashEntryList []CertHashEntry, err error)
	GetRemoteAccessConnectionStatus() (RAStatus GetRemoteAccessConnectionStatusResponse, err error)
	GetLANInterfaceSettings(useWireless bool) (LANInterface GetLANInterfaceSettingsResponse, err error)
	GetLocalSystemAccount() (localAccount GetLocalSystemAccountResponse, err error)
	Unprovision() (mode int, err error)
}

func NewCommand() Command {
	return Command{
		Heci: heci.NewDriver(),
	}
}

func (pthi Command) Open(useLME bool) error {
	err := pthi.Heci.Init(useLME, false)
	return err
}

func (pthi Command) OpenWatchdog() error {
	err := pthi.Heci.Init(false, true)
	return err
}

func (pthi Command) Close() {
	pthi.Heci.Close()
}

func (pthi Command) Call(command []byte, commandSize uint32) (result []byte, err error) {
	size := pthi.Heci.GetBufferSize()

	bytesWritten, err := pthi.Heci.SendMessage(command, &commandSize)
	if err != nil {
		return nil, err
	}

	if bytesWritten != uint32(len(command)) {
		return nil, errors.New("amt internal error")
	}

	readBuffer := make([]byte, size)

	bytesRead, err := pthi.Heci.ReceiveMessage(readBuffer, &size)
	if err != nil {
		return nil, err
	}

	if bytesRead == 0 {
		return nil, errors.New("empty response from AMT")
	}

	return readBuffer, nil
}
func (pthi Command) Send(command []byte, commandSize uint32) (err error) {
	bytesWritten, err := pthi.Heci.SendMessage(command, &commandSize)
	if err != nil {
		return err
	}

	if bytesWritten != uint32(len(command)) {
		return errors.New("amt internal error")
	}

	return nil
}
func (pthi Command) Receive() (result []byte, bytesRead uint32, err error) {
	size := pthi.Heci.GetBufferSize()

	readBuffer := make([]byte, size)

	bytesRead, err = pthi.Heci.ReceiveMessage(readBuffer, &size)
	if err != nil {
		return nil, 0, err
	}

	return readBuffer, bytesRead, nil
}

func CreateRequestHeader(command uint32, length uint32) MessageHeader {
	return MessageHeader{
		Version: Version{
			MajorNumber: 1,
			MinorNumber: 1,
		},
		Reserved: 0,
		Command: CommandFormat{
			val: command,
		},
		Length: length,
	}
}

func (pthi Command) GetCodeVersions() (GetCodeVersionsResponse, error) {
	command := GetRequest{
		Header: CreateRequestHeader(CODE_VERSIONS_REQUEST, 0),
	}

	var bin_buf bytes.Buffer

	binary.Write(&bin_buf, binary.LittleEndian, command)

	result, err := pthi.Call(bin_buf.Bytes(), GET_REQUEST_SIZE)
	if err != nil {
		return GetCodeVersionsResponse{}, err
	}

	buf2 := bytes.NewBuffer(result)
	response := GetCodeVersionsResponse{
		Header: readHeaderResponse(buf2),
	}
	binary.Read(buf2, binary.LittleEndian, &response.CodeVersion)

	return response, nil
}

func (pthi Command) GetUUID() (uuid string, err error) {
	command := GetRequest{
		Header: CreateRequestHeader(GET_UUID_REQUEST, 0),
	}

	var bin_buf bytes.Buffer

	binary.Write(&bin_buf, binary.LittleEndian, command)

	result, err := pthi.Call(bin_buf.Bytes(), GET_REQUEST_SIZE)
	if err != nil {
		return "", err
	}

	buf2 := bytes.NewBuffer(result)
	response := GetUUIDResponse{
		Header: readHeaderResponse(buf2),
	}

	binary.Read(buf2, binary.LittleEndian, &response.UUID)

	return string(([]byte)(response.UUID[:])), nil
}

func (pthi Command) GetControlMode() (state int, err error) {
	command := GetRequest{
		Header: CreateRequestHeader(GET_CONTROL_MODE_REQUEST, 0),
	}

	var bin_buf bytes.Buffer

	binary.Write(&bin_buf, binary.LittleEndian, command)

	result, err := pthi.Call(bin_buf.Bytes(), GET_REQUEST_SIZE)
	if err != nil {
		return -1, err
	}

	buf2 := bytes.NewBuffer(result)
	response := GetControlModeResponse{
		Header: readHeaderResponse(buf2),
	}

	binary.Read(buf2, binary.LittleEndian, &response.State)

	return int(response.State), nil
}

func (pthi Command) GetIsAMTEnabled() (uint8, error) {
	command := GetStateIndependenceIsChangeToAMTEnabledRequest{
		Command:       0x5,
		ByteCount:     0x2,
		SubCommand:    0x51,
		VersionNumber: 0x10,
	}

	var bin_buf bytes.Buffer

	binary.Write(&bin_buf, binary.LittleEndian, command)
	result, err := pthi.Call(bin_buf.Bytes(), uint32(bin_buf.Len()))

	if err != nil {
		return uint8(0), err
	}

	buf2 := bytes.NewBuffer(result)

	var resBuffer uint8

	binary.Read(buf2, binary.LittleEndian, &resBuffer)

	return resBuffer, nil
}

func (pthi Command) SetAmtOperationalState(state AMTOperationalState) (Status, error) {
	command := SetAmtOperationalState{
		Command:       0x5,
		ByteCount:     0x3,
		SubCommand:    0x53,
		VersionNumber: 0x10,
		Enabled:       state,
	}

	var bin_buf bytes.Buffer

	binary.Write(&bin_buf, binary.LittleEndian, command)
	//result, err := pthi.Call(bin_buf.Bytes(), 32)
	result, err := pthi.Call(bin_buf.Bytes(), uint32(bin_buf.Len()))
	if err != nil {
		return Status(0), err
	}

	buf2 := bytes.NewBuffer(result)

	var dontcare uint8

	var status Status

	binary.Read(buf2, binary.LittleEndian, &dontcare)
	binary.Read(buf2, binary.LittleEndian, &dontcare)
	binary.Read(buf2, binary.LittleEndian, &dontcare)
	binary.Read(buf2, binary.LittleEndian, &dontcare)
	binary.Read(buf2, binary.LittleEndian, &status)

	return status, nil
}

func (pthi Command) Unprovision() (state int, err error) {
	command := UnprovisionRequest{
		Header: CreateRequestHeader(UNPROVISION_REQUEST, 4),
		Mode:   0,
	}

	var bin_buf bytes.Buffer

	binary.Write(&bin_buf, binary.LittleEndian, command)

	result, err := pthi.Call(bin_buf.Bytes(), GET_REQUEST_SIZE+4) // Extra 4 bytes for the mode
	if err != nil {
		return -1, err
	}

	buf2 := bytes.NewBuffer(result)
	response := UnprovisionResponse{
		Header: readHeaderResponse(buf2),
	}

	binary.Read(buf2, binary.LittleEndian, &response.State)

	return int(response.State), nil
}

func readHeaderResponse(header *bytes.Buffer) ResponseMessageHeader {
	response := ResponseMessageHeader{}

	binary.Read(header, binary.LittleEndian, &response.Header.Version.MajorNumber)
	binary.Read(header, binary.LittleEndian, &response.Header.Version.MinorNumber)
	binary.Read(header, binary.LittleEndian, &response.Header.Reserved)
	binary.Read(header, binary.LittleEndian, &response.Header.Command.val)
	binary.Read(header, binary.LittleEndian, &response.Header.Length)
	binary.Read(header, binary.LittleEndian, &response.Status)

	return response
}

func (pthi Command) GetDNSSuffix() (suffix string, err error) {
	command := GetRequest{
		Header: CreateRequestHeader(GET_PKI_FQDN_SUFFIX_REQUEST, 0),
	}

	var bin_buf bytes.Buffer

	binary.Write(&bin_buf, binary.LittleEndian, command)

	result, err := pthi.Call(bin_buf.Bytes(), GET_REQUEST_SIZE)
	if err != nil {
		return "", err
	}

	buf2 := bytes.NewBuffer(result)
	response := GetPKIFQDNSuffixResponse{
		Header: readHeaderResponse(buf2),
	}

	binary.Read(buf2, binary.LittleEndian, &response.Suffix.Length)
	binary.Read(buf2, binary.LittleEndian, &response.Suffix.Buffer)

	if int(response.Suffix.Length) > 0 {
		return string(response.Suffix.Buffer[:response.Suffix.Length]), nil
	}

	return "", nil
}

func (pthi Command) enumerateHashHandles() (AMTHashHandles, error) {
	// Enumerate a list of hash handles to request from
	enumerateCommand := GetRequest{
		Header: CreateRequestHeader(ENUMERATE_HASH_HANDLES_REQUEST, 0),
	}

	var EnumerateBin_buf bytes.Buffer

	binary.Write(&EnumerateBin_buf, binary.LittleEndian, enumerateCommand)

	enumerateResult, err := pthi.Call(EnumerateBin_buf.Bytes(), GET_REQUEST_SIZE)
	if err != nil {
		return AMTHashHandles{}, err
	}

	enumerateBuf2 := bytes.NewBuffer(enumerateResult)
	enumerateResponse := GetHashHandlesResponse{
		Header: readHeaderResponse(enumerateBuf2),
	}

	binary.Read(enumerateBuf2, binary.LittleEndian, &enumerateResponse.HashHandles.Length)
	binary.Read(enumerateBuf2, binary.LittleEndian, &enumerateResponse.HashHandles.Handles)

	return enumerateResponse.HashHandles, nil
}
func (pthi Command) GetCertificateHashes(hashHandles AMTHashHandles) (hashEntryList []CertHashEntry, err error) {
	if hashHandles.Length == 0 {
		hashHandles, err = pthi.enumerateHashHandles()
		if err != nil {
			return []CertHashEntry{}, err
		}
	}
	// Request from the enumerated list and return cert hashes
	for i := 0; i < int(hashHandles.Length); i++ {
		commandSize := (uint32)(16)
		command := GetCertHashEntryRequest{
			Header:     CreateRequestHeader(GET_CERTHASH_ENTRY_REQUEST, 4),
			HashHandle: hashHandles.Handles[i],
		}

		var bin_buf bytes.Buffer

		binary.Write(&bin_buf, binary.LittleEndian, command)

		result, err := pthi.Call(bin_buf.Bytes(), commandSize)
		if err != nil {
			emptyHashList := []CertHashEntry{}
			return emptyHashList, err
		}

		buf2 := bytes.NewBuffer(result)
		response := GetCertHashEntryResponse{
			Header: readHeaderResponse(buf2),
		}

		binary.Read(buf2, binary.LittleEndian, &response.Hash.IsDefault)
		binary.Read(buf2, binary.LittleEndian, &response.Hash.IsActive)
		binary.Read(buf2, binary.LittleEndian, &response.Hash.CertificateHash)
		binary.Read(buf2, binary.LittleEndian, &response.Hash.HashAlgorithm)
		binary.Read(buf2, binary.LittleEndian, &response.Hash.Name.Length)
		binary.Read(buf2, binary.LittleEndian, &response.Hash.Name.Buffer)

		hashEntryList = append(hashEntryList, response.Hash)
	}

	return hashEntryList, nil
}

func (pthi Command) GetRemoteAccessConnectionStatus() (RAStatus GetRemoteAccessConnectionStatusResponse, err error) {
	command := GetRequest{
		Header: CreateRequestHeader(GET_REMOTE_ACCESS_CONNECTION_STATUS_REQUEST, 0),
	}

	var bin_buf bytes.Buffer

	binary.Write(&bin_buf, binary.LittleEndian, command)

	result, err := pthi.Call(bin_buf.Bytes(), GET_REQUEST_SIZE)
	if err != nil {
		emptyResponse := GetRemoteAccessConnectionStatusResponse{}
		return emptyResponse, err
	}

	buf2 := bytes.NewBuffer(result)
	response := GetRemoteAccessConnectionStatusResponse{
		Header: readHeaderResponse(buf2),
	}

	binary.Read(buf2, binary.LittleEndian, &response.NetworkStatus)
	binary.Read(buf2, binary.LittleEndian, &response.RemoteStatus)
	binary.Read(buf2, binary.LittleEndian, &response.RemoteTrigger)
	binary.Read(buf2, binary.LittleEndian, &response.MPSHostname.Length)
	binary.Read(buf2, binary.LittleEndian, &response.MPSHostname.Buffer)

	return response, nil
}

func (pthi Command) GetLANInterfaceSettings(useWireless bool) (LANInterface GetLANInterfaceSettingsResponse, err error) {
	commandSize := (uint32)(16)

	command := GetLANInterfaceSettingsRequest{
		Header:         CreateRequestHeader(GET_LAN_INTERFACE_SETTINGS_REQUEST, 4),
		InterfaceIndex: 0,
	}
	if useWireless {
		command.InterfaceIndex = 1
	}

	var bin_buf bytes.Buffer

	binary.Write(&bin_buf, binary.LittleEndian, command)

	result, err := pthi.Call(bin_buf.Bytes(), commandSize)
	if err != nil {
		emptySettings := GetLANInterfaceSettingsResponse{}
		return emptySettings, err
	}

	buf2 := bytes.NewBuffer(result)
	response := GetLANInterfaceSettingsResponse{
		Header: readHeaderResponse(buf2),
	}

	binary.Read(buf2, binary.LittleEndian, &response.Enabled)
	binary.Read(buf2, binary.LittleEndian, &response.Ipv4Address)
	binary.Read(buf2, binary.LittleEndian, &response.DhcpEnabled)
	binary.Read(buf2, binary.LittleEndian, &response.DhcpIpMode)
	binary.Read(buf2, binary.LittleEndian, &response.LinkStatus)
	binary.Read(buf2, binary.LittleEndian, &response.MacAddress)

	return response, nil
}

func (pthi Command) GetLocalSystemAccount() (localAccount GetLocalSystemAccountResponse, err error) {
	commandSize := (uint32)(52)
	command := GetLocalSystemAccountRequest{
		Header: CreateRequestHeader(GET_LOCAL_SYSTEM_ACCOUNT_REQUEST, 40),
	}

	var bin_buf bytes.Buffer

	binary.Write(&bin_buf, binary.LittleEndian, command)

	result, err := pthi.Call(bin_buf.Bytes(), commandSize)
	if err != nil {
		emptyAccount := GetLocalSystemAccountResponse{}
		return emptyAccount, err
	}

	buf2 := bytes.NewBuffer(result)
	response := GetLocalSystemAccountResponse{
		Header: readHeaderResponse(buf2),
	}

	binary.Read(buf2, binary.LittleEndian, &response.Account.Username)
	binary.Read(buf2, binary.LittleEndian, &response.Account.Password)

	return response, nil
}
