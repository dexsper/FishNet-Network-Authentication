//Copyright 2023 Kostasel
//See license.txt for license details

using FishNet.Broadcast;

namespace NetworkAuth
{
    //Client -> Server
    public struct HandshakeRequestBroadcast : IBroadcast
    {
        public byte[] PublicKey;
    }

    public struct HandshakeResponseBroadcast : IBroadcast
    {
        public byte[] PublicKey;
        public byte[] Randombytes;
    }

    public struct RegisterRequestBroadcast : IBroadcast
    {
        public byte[] Username;
        public int usr_pad_count;
        public byte[] Password;
        public int pass_pad_count;

        public string Email;
    }

    public struct RegisterResponseBroadcast : IBroadcast
    {
        public bool Registered;
    }

    public struct AuthenticationRequestBroadcast : IBroadcast
    {
        public byte[] Username;
        public int usr_pad_count;
        public byte[] Password;
        public int pass_pad_count;
    }

    public struct AuthenticationResponseBroadcast : IBroadcast
    {
        public bool Authenticated;
    }
}