//Copyright 2023 Kostasel
//See license.txt for license details

using FishNet;
using FishNet.Managing;
using FishNet.Transporting;
using NetworkAuth.Crypto;
using System;
using System.Text;
using FishNet.Managing.Client;
using UnityEngine;

namespace NetworkAuth.ClientAuth
{
    [DisallowMultipleComponent]
    public class ClientAuthenticator : MonoBehaviour
    {
        private bool _handshakeCompleted;
        private bool _authenticationCompleted;

        private NetworkManager _networkManager;
        private ClientManager _clientManager;
        private static Encryptor _crypto;

        private void Start()
        {
            _networkManager = InstanceFinder.NetworkManager;
            _clientManager = _networkManager.ClientManager;

            _clientManager.OnClientConnectionState += OnClientConnectionState;
        }

        private void OnClientConnectionState(ClientConnectionStateArgs args)
        {
            switch (args.ConnectionState)
            {
                case LocalConnectionState.Started when _authenticationCompleted:
                    return;
                case LocalConnectionState.Started:
                    {
                        _clientManager.RegisterBroadcast<HandshakeResponseBroadcast>(OnHandshakeResponseBroadcast);
                        _clientManager.RegisterBroadcast<AuthenticationResponseBroadcast>(
                            OnAuthenticationResponseBroadcast);

                        _networkManager.Log("Listening for Handshake response...");
                        _networkManager.Log("Listening for Authentication response...");

                        _crypto = new Encryptor(12, 6);
                        HandshakeRequestBroadcast handshake = new()
                        {
                            PublicKey = Transforms.TransformValueArray(_crypto.PublicKey).ToArray()
                        };

                        _networkManager.Log("Sending handshake request to server...");
                        _clientManager.Broadcast(handshake);
                        break;
                    }
                case LocalConnectionState.Stopped:
                    _networkManager.Log("Stopped listening for responses from server...");

                    _clientManager.UnregisterBroadcast<HandshakeResponseBroadcast>(OnHandshakeResponseBroadcast);
                    _clientManager.UnregisterBroadcast<AuthenticationResponseBroadcast>(
                        OnAuthenticationResponseBroadcast);

                    _crypto?.Dispose(true);
                    _authenticationCompleted = false;

                    InstanceFinder.NetworkManager.Log("Client Authenticator Stopped.");
                    break;
            }
        }

        private void OnHandshakeResponseBroadcast(HandshakeResponseBroadcast hsk, Channel channel)
        {
            InstanceFinder.NetworkManager.Log("Received handshake response from server...");

            byte[] data = Transforms.InvertTransformValueArray(hsk.Randombytes).ToArray();
            Span<byte> rndbytes = new Span<byte>(data, 0, 64);
            Span<byte> iv = new Span<byte>(data, 64, 16);

            _networkManager.Log("Computing the SharedKey key based on the public key received from server...");
            _crypto.ComputeSharedKey(Transforms.InvertTransformValueArray(hsk.PublicKey).ToArray(), rndbytes.ToArray());
            _crypto.iv = iv.ToArray();

            if (_crypto.PublicKey.Length > 0 && _crypto.GetSharedKey().Length > 0)
            {
                _handshakeCompleted = true;
                _networkManager.Log("Handshake Successfully.");
            }
            else
            {
                _handshakeCompleted = false;
                _networkManager.ClientManager.StopConnection();
                _networkManager.LogError("Handshake Failed.");
            }
        }

        private void OnAuthenticationResponseBroadcast(AuthenticationResponseBroadcast arb, Channel channel)
        {
            _networkManager.Log("Received authentication response from server...");
            bool result = arb.Authenticated;

            switch (result)
            {
                case true:
                    _networkManager.Log("Authenticated Successfully.");
                    break;
                default:
                    _networkManager.LogWarning("Authentication Failed.");
                    break;
            }

            _authenticationCompleted = true;
            _networkManager.Log("Authentication Completed.");
        }

        public void AuthenticateClient(string username, string password)
        {
            if (!_handshakeCompleted)
            {
                InstanceFinder.NetworkManager.LogError("Handshaking failed. Cannot Authenticate.");
                return;
            }

            int blocksize = 16;
            byte[] usrname = Encoding.UTF8.GetBytes(username);
            byte[] pass = Encoding.UTF8.GetBytes(password);

            AuthenticationRequestBroadcast arb = new()
            {
                Username = _crypto.EncryptData(usrname),
                usr_pad_count = (blocksize - usrname.Length),
                Password = _crypto.EncryptData(pass),
                pass_pad_count = (blocksize - pass.Length)
            };

            InstanceFinder.NetworkManager.Log("Sending Authentication request to server...");
            InstanceFinder.NetworkManager.ClientManager.Broadcast(arb);
        }

        public void RegisterClient(string username, string password, string email)
        {
            if (!_handshakeCompleted)
            {
                InstanceFinder.NetworkManager.LogError("Handshaking failed. Cannot Authenticate.");
                return;
            }

            int blocksize = 16;
            byte[] usrname = Encoding.UTF8.GetBytes(username);
            byte[] pass = Encoding.UTF8.GetBytes(password);

            RegisterRequestBroadcast arb = new()
            {
                Username = _crypto.EncryptData(usrname),
                usr_pad_count = blocksize - usrname.Length,
                Password = _crypto.EncryptData(pass),
                pass_pad_count = blocksize - pass.Length,
                Email = email
            };

            InstanceFinder.NetworkManager.Log("Sending Register request to server...");
            InstanceFinder.NetworkManager.ClientManager.Broadcast(arb);
        }
    }
}
