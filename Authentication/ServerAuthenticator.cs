//Copyright 2023 Kostasel
//See license.txt for license details

using FishNet.Authenticating;
using FishNet.Connection;
using FishNet.Managing;
using FishNet.Transporting;
using NetworkAuth.Crypto;
using System;
using System.Text;
using UnityEngine;

namespace NetworkAuth.ServerAuth
{
    /// <summary>
    /// NetworkAuth Authenticator
    /// </summary>
    [DisallowMultipleComponent]
    public class ServerAuthenticator : Authenticator
    {
        private readonly Dictionary<int, bool> _handshakeCompleted = new();
        private NetworkManager _manager;
        private Encryptor _crypto;
        private Server.Server _server;

        public override event Action<NetworkConnection, bool> OnAuthenticationResult;

        public override void InitializeOnce(NetworkManager networkManager)
        {
            base.InitializeOnce(networkManager);

            _manager = networkManager;
            _server = _manager.GetComponent<Server.Server>();
            _manager.ServerManager.OnServerConnectionState += OnServerConnectionState;
            _manager.ServerManager.OnRemoteConnectionState += OnRemoteConnectionState;
        }

        private void OnRemoteConnectionState(NetworkConnection conn, RemoteConnectionStateArgs args)
        {
            if (args.ConnectionState != RemoteConnectionState.Stopped)
                return;

            if (_handshakeCompleted.ContainsKey(conn.ClientId))
            {
                _handshakeCompleted[conn.ClientId] = false;
            }
        }

        private void OnServerConnectionState(ServerConnectionStateArgs args)
        {
            switch (args.ConnectionState)
            {
                case LocalConnectionState.Started:
                    _crypto = new Encryptor(12, 6);

                    _manager.ServerManager.RegisterBroadcast<HandshakeRequestBroadcast>(OnHandshakeRequestBroadcast,
                        false);
                    _manager.ServerManager.RegisterBroadcast<AuthenticationRequestBroadcast>(
                        OnAuthenticationRequestBroadcast, false);
                    _manager.ServerManager.RegisterBroadcast<RegisterRequestBroadcast>(
                        OnRegisterRequestBroadcast, false);

                    _manager.Log("Listening for Handshake requests...");
                    _manager.Log("Listening for Authentication requests...");
                    _manager.Log("Listening for Register requests..");
                    break;
                case LocalConnectionState.Stopped:
                    _manager.ServerManager.UnregisterBroadcast<HandshakeRequestBroadcast>(OnHandshakeRequestBroadcast);
                    _manager.Log("Stopped Listening for Handshake request...");
                    _manager.ServerManager.UnregisterBroadcast<AuthenticationRequestBroadcast>(
                        OnAuthenticationRequestBroadcast);
                    _manager.Log("Stopped Listening for Authentication request...");
                    break;
            }
        }

        private async void OnRegisterRequestBroadcast(NetworkConnection conn, RegisterRequestBroadcast rrb,
            Channel channel)
        {
            if (!_handshakeCompleted.TryGetValue(conn.ClientId, out bool handshakeCompleted) || !handshakeCompleted)
            {
                NetworkManager.LogWarning("A Client tried to authenticate without previously completing handshaking.");
                return;
            }

            if (conn.Authenticated)
            {
                conn.Disconnect(true);
                NetworkManager.LogWarning("Client Disconnected. Reason: Already Authenticated.");
                return;
            }

            NetworkManager.Log("Try register client account.");

            string username = Encoding.UTF8.GetString(_crypto.DecryptData(rrb.Username, rrb.usr_pad_count));
            string password = Encoding.UTF8.GetString(_crypto.DecryptData(rrb.Username, rrb.pass_pad_count));
            string email = rrb.Email;
            bool registered = false;

            Account existsAccount =
                await _server.Database.FindAsync<Account>(x => x.Email == email || x.Username == username);

            if (existsAccount == null)
            {
                Hash.CreatePasswordHash(password, out byte[] passwordHash, out byte[] passwordSalt);

                Account account = new Account
                {
                    Username = username,
                    Email = email,
                    PasswordHash = passwordHash,
                    PasswordSalt = passwordSalt
                };

                await _server.Database.InsertAsync(account);
                await _server.Database.UpdateAsync(account);

                registered = true;
            }

            RegisterResponseBroadcast responseBroadcast = new RegisterResponseBroadcast
            {
                Registered = registered
            };

            NetworkManager.Log("Sending Register response to client...");
            NetworkManager.ServerManager.Broadcast(conn, responseBroadcast, false);

            if (!registered)
                return;

            OnAuthenticationRequestBroadcast(conn, new AuthenticationRequestBroadcast
            {
                Username = rrb.Username,
                Password = rrb.Password,
                usr_pad_count = rrb.usr_pad_count,
                pass_pad_count = rrb.pass_pad_count,
            }, channel);
        }

        private void OnHandshakeRequestBroadcast(NetworkConnection conn, HandshakeRequestBroadcast hsk, Channel channel)
        {
            NetworkManager.Log("Received Handshake request from client...");
            Span<byte> result = stackalloc byte[64 + 16];
            byte[] data = new byte[64 + 16];
            result.Clear();

            NetworkManager.Log("Computing the SharedKey key based on the public key received from client...");
            _crypto.ComputeShared(Transforms.InvertTransformValueArray(hsk.PublicKey).ToArray());

            if (!_handshakeCompleted.TryAdd(conn.ClientId, true))
                _handshakeCompleted[conn.ClientId] = true;

            NetworkManager.Log("Sending Server Public Key as a response to the handshake request from client...");

            Array.ConstrainedCopy(_crypto.GetRandomSalt(), 0, data, 0, 64);
            Array.ConstrainedCopy(_crypto.GetIV(), 0, data, 64, 16);
            result = new Span<byte>(data);

            HandshakeResponseBroadcast hrb = new()
            {
                PublicKey = Transforms.TransformValueArray(_crypto.PublicKey).ToArray(),
                Randombytes = Transforms.TransformValueArray(result.ToArray()).ToArray()
            };

            NetworkManager.ServerManager.Broadcast(conn, hrb, false);
            Array.Clear(data, 0, data.Length);
        }

        private async void OnAuthenticationRequestBroadcast(NetworkConnection conn, AuthenticationRequestBroadcast arb,
            Channel channel)
        {
            if (!_handshakeCompleted.TryGetValue(conn.ClientId, out bool handshakeCompleted) || !handshakeCompleted)
            {
                NetworkManager.LogWarning("A Client tried to authenticate without previously completing handshaking.");
                return;
            }

            if (conn.Authenticated)
            {
                conn.Disconnect(true);
                NetworkManager.LogWarning("Client Disconnected. Reason: Already Authenticated.");
                return;
            }

            NetworkManager.Log("Validating client details...");

            string username = Encoding.UTF8.GetString(_crypto.DecryptData(arb.Username, arb.usr_pad_count));
            string password = Encoding.UTF8.GetString(_crypto.DecryptData(arb.Password, arb.pass_pad_count));

            Account existsAccount =
                await _server.Database.FindAsync<Account>(x => x.Username == username);


            bool authenticated = existsAccount != null &&
                                 Hash.VerifyPasswordHash(password, existsAccount.PasswordHash,
                                     existsAccount.PasswordSalt);


            AuthenticationResponseBroadcast responseBroadcast = new()
            {
                Authenticated = authenticated
            };

            NetworkManager.Log("Sending Authentication response to client...");
            NetworkManager.ServerManager.Broadcast(conn, responseBroadcast, false);

            OnAuthenticationResult?.Invoke(conn, authenticated);
        }
    }
}