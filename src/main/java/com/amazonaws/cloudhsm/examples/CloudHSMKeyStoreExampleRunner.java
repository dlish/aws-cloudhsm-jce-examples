/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package com.amazonaws.cloudhsm.examples;

import com.cavium.cfm2.CFM2Exception;
import com.cavium.cfm2.Util;
import com.cavium.key.*;

import java.io.*;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

/**
 * KeyStoreExampleRunner demonstrates how to load a keystore, and associate a certificate with a
 * key in that keystore.
 *
 * This example relies on implicit credentials, so you must setup your environment correctly.
 *
 * https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-library-install.html#java-library-credentials
 */
public class CloudHSMKeyStoreExampleRunner {

     private static String helpString = "KeyStoreExampleRunner\n" +
            "This sample demonstrates how to load and store keys using a keystore.\n\n" +
            "Options\n" +
            "\t--help\t\t\t\t\tDisplay this message.\n" +
            "\t--store <filename>\t\tPath of the keystore.\n" +
            "\t--password <password>\tPassword for the keystore (not your CU password).\n" +
            "\t--label <label>\t\t\tLabel to store the key and certificate under.\n" +
             "\t--cert <cert-filename>\tCertificate file name to associate with private key\n" +
            "\t--list\t\t\t\t\tList all the keys in the keystore.\n\n";

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            help();
            return;
        }

        String keystoreFile = null;
        String password = null;
        String label = null;
        String certFileName = null;
        long handle = 0;
        boolean list = false;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--store":
                    keystoreFile = args[++i];
                    break;
                case "--password":
                    password = args[++i];
                    break;
                case "--label":
                    label = args[++i];
                    break;
                case "--list":
                    list = true;
                    break;
                case "--cert":
                    certFileName = args[++i];
                    break;
                case "--help":
                    help();
                    return;
            }
        }

        Security.addProvider(new com.cavium.provider.CaviumProvider());
        KeyStore keyStore = KeyStore.getInstance("CloudHSM");

        if (null == keystoreFile || null == password) {
            help();
            return;
        }

        if (list) {
            listKeys(keystoreFile, password);
            return;
        }

        if (null == label) {
            label = "platform";
        }

        if (null == certFileName) {
            help();
            return;
        } else {
            File tempFile = new File(certFileName);
            boolean exists = tempFile.exists();
            if (!exists) {
                System.out.println(certFileName + " was not found");
                return;
            }
        }

        /**
         * This call to keyStore.load() will open the pkcs12 keystore with the supplied
         * password and connect to the HSM. The CU credentials must be specified using
         * standard CloudHSM login methods.
         */
        try {
            FileInputStream instream = new FileInputStream(keystoreFile);
            keyStore.load(instream, password.toCharArray());
        } catch (FileNotFoundException ex) {
            System.err.println("Keystore not found, loading an empty store");
            keyStore.load(null, null);
        }

        PasswordProtection passwd = new PasswordProtection(password.toCharArray());
        System.out.println("Searching for example key and certificate...");

        handle = getHandleByLabel(label);

        PrivateKeyEntry keyEntry = null;
        try {
            keyEntry = (PrivateKeyEntry) keyStore.getEntry(label, passwd);
        } catch (Exception e) {
            System.out.println(e);
        }

        if (null == keyEntry) {
            CaviumKey key = getKeyByHandle(handle);
            System.out.println("Found key: " + key.getLabel());

            /**
             * Generate a certificate and associate the chain with the private key.
             */
            InputStream in = new FileInputStream(certFileName);
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) factory.generateCertificate(in);

            Certificate[] chain = new Certificate[1];
            chain[0] = cert;
            PrivateKeyEntry entry = new PrivateKeyEntry((CaviumRSAPrivateKey) key, chain);

            /**
             * Set the entry using the label as the alias and save the store.
             * The alias must match the private key label.
             */
            keyStore.setEntry(label, entry, passwd);

            FileOutputStream outstream = new FileOutputStream(keystoreFile);
            keyStore.store(outstream, password.toCharArray());
            outstream.close();

            keyEntry = (PrivateKeyEntry) keyStore.getEntry(label, passwd);
        }

        long handles = ((CaviumKey) keyEntry.getPrivateKey()).getHandle();
        String name = keyEntry.getCertificate().toString();
        System.out.printf("Found private key %d with certificate %s%n", handles, name);
    }

    private static void help() {
        System.out.println(helpString);
    }

    /**
     * List all the keys in the keystore.
     */
    private static void listKeys(String keystoreFile, String password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("CloudHSM");

        try {
            FileInputStream instream = new FileInputStream(keystoreFile);
            keyStore.load(instream, password.toCharArray());
        } catch (FileNotFoundException ex) {
            System.err.println("Keystore not found, loading an empty store");
            keyStore.load(null, null);
        }

        for(Enumeration<String> entry = keyStore.aliases(); entry.hasMoreElements();) {
            System.out.println(entry.nextElement());
        }
    }

    private static long getHandleByLabel(String label) {
        // Using the supplied label, find the associated key handle.
        // The handle for the *first* key found using the label will be the handle returned.
        // If multiple keys have the same label, only the first key can be returned.
        long[] handles = { 0 };
        try {
            Util.findKey(label, handles);
        } catch (CFM2Exception ex) {
            if (CFM2Exception.isAuthenticationFailure(ex)) {
                System.out.println("Could not find credentials to login to the HSM");
                System.exit(1);
            }
        }
        return handles[0];
    }

    /**
     * Get an existing key from the HSM using a key handle.
     * @param handle The key handle in the HSM.
     * @return CaviumKey object
     */
    private static CaviumKey getKeyByHandle(long handle) throws CFM2Exception {
        // There is no direct method to load a key, but there is a method to load key attributes.
        // Using the key attributes and the handle, a new CaviumKey object can be created. This method shows
        // how to create a specific key type based on the attributes.
        byte[] keyAttribute = Util.getKeyAttributes(handle);
        CaviumKeyAttributes cka = new CaviumKeyAttributes(keyAttribute);

        if(cka.getKeyType() == CaviumKeyAttributes.KEY_TYPE_AES) {
            return new CaviumAESKey(handle, cka);
        }
        else if(cka.getKeyType() == CaviumKeyAttributes.KEY_TYPE_RSA &&
                cka.getKeyClass() == CaviumKeyAttributes.CLASS_PRIVATE_KEY) {
            return new CaviumRSAPrivateKey(handle, cka);
        }
        else if(cka.getKeyType() == CaviumKeyAttributes.KEY_TYPE_RSA &&
                cka.getKeyClass() == CaviumKeyAttributes.CLASS_PUBLIC_KEY) {
            return new CaviumRSAPublicKey(handle, cka);
        }
        else if(cka.getKeyType() == CaviumKeyAttributes.KEY_TYPE_EC &&
                cka.getKeyClass() == CaviumKeyAttributes.CLASS_PRIVATE_KEY) {
            return new CaviumECPrivateKey(handle, cka);
        }
        else if(cka.getKeyType() == CaviumKeyAttributes.KEY_TYPE_EC &&
                cka.getKeyClass() == CaviumKeyAttributes.CLASS_PUBLIC_KEY) {
            return new CaviumECPublicKey(handle, cka);
        }
        else if(cka.getKeyType() == CaviumKeyAttributes.KEY_TYPE_GENERIC_SECRET) {
            return new CaviumAESKey(handle, cka);
        }

        return null;
    }
}
