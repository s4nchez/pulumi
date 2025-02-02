﻿// Copyright 2016-2021, Pulumi Corporation

using System.Collections.Generic;

namespace Pulumi.Automation
{
    public class StackSettings
    {
        /// <summary>
        /// This stack's secrets provider.
        /// </summary>
        public string? SecretsProvider { get; set; }

        /// <summary>
        /// This is the KMS-encrypted ciphertext for the data key used for secrets
        /// encryption. Only used for cloud-based secrets providers.
        /// </summary>
        public string? EncryptedKey { get; set; }

        /// <summary>
        /// This is this stack's base64 encoded encryption salt. Only used for
        /// passphrase-based secrets providers.
        /// </summary>
        public string? EncryptionSalt { get; set; }

        /// <summary>
        /// This is an optional configuration bag.
        /// </summary>
        public IDictionary<string, StackSettingsConfigValue>? Config { get; set; }
    }
}
