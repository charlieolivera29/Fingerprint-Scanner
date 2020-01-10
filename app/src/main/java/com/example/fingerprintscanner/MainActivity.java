package com.example.fingerprintscanner;

import android.Manifest;
import android.annotation.TargetApi;
import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.hardware.biometrics.BiometricPrompt;
import android.hardware.fingerprint.FingerprintManager;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Bundle;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.core.content.ContextCompat;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.text.format.Formatter;
import android.widget.ImageView;
import android.widget.TextView;

import java.io.IOException;
import java.net.NetworkInterface;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

@RequiresApi(api = Build.VERSION_CODES.M)
public class MainActivity extends AppCompatActivity {

    private String MY_KEY_NAME = "AndroidKey" ;
    private TextView mHeaderLabel;
    private ImageView mFingerPrintImage;
    private TextView mParaLabel;

    private FingerprintManager fingerprintManager; // check 2
    private KeyguardManager keyguardManager; // check 3
    private KeyStore keyStore;
    private Cipher cipher;

    //check 1: Android version should be greater or equal to marshmallow
    //check 2: Device has finger print scanner
    //check 3: Have permission to use the finger print in the app
    //check 4: Lock screen is secured with  atleast 1 type of lock
    //check 5: atleast 1 finger print is registered

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

//        Utils.getMACAddress("wlan0");

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M){ // check 1 // check if the Android version is above marshmallow(6) version

            fingerprintManager = (FingerprintManager) getSystemService(FINGERPRINT_SERVICE); // check 2

            if (!fingerprintManager.isHardwareDetected()) { // check if the External device is mounted
                setContentView(R.layout.login_page);
//                mParaLabel.setText("Fingerprint Scanner is not detected in device"); // check 2
            } else {
                setContentView(R.layout.content_main);
                keyguardManager = (KeyguardManager) getSystemService(KEYGUARD_SERVICE); // check 3

                mHeaderLabel = findViewById(R.id.headingLabel);
                mFingerPrintImage = findViewById(R.id.fingerprintImage);
                mParaLabel = findViewById(R.id.paraLabel);

                if (ContextCompat.checkSelfPermission(this, Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) { // check if the user allow permission to app to use finger print
                    mParaLabel.setText("Permission not granted to use Fingerprint Scanner"); // check 3
                } else if (!keyguardManager.isKeyguardSecure()){ // check if phone has atleast 1 type of lock
                    mParaLabel.setText("Add lock to your phone in Settings");
                } else if (!fingerprintManager.hasEnrolledFingerprints()) {
                    mParaLabel.setText("You should add atleast 1 Fingerprint to use this feature");
                } else {
//                    mParaLabel.setText("Please place your Finger on the Scanner to Access the App");
                    generateKey();

                    if (cipherInit()) {
                        FingerprintManager.CryptoObject cryptoObject = new FingerprintManager.CryptoObject(cipher);
                        FingerprintHandler fingerprintHandler = new FingerprintHandler(this);
                        fingerprintHandler.startAuth(fingerprintManager, cryptoObject);
                    }
                }//permission acquired
            }//end hardware detection
        }//end build version


    }

    @TargetApi(Build.VERSION_CODES.M)
    private void generateKey(){
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            KeyGenerator keyGenerator = KeyGenerator.getInstance( KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            keyStore.load(null);
            keyGenerator.init(new KeyGenParameterSpec.Builder(MY_KEY_NAME, KeyProperties.PURPOSE_ENCRYPT |                                                        KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC) .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());
            keyGenerator.generateKey();
        } catch (KeyStoreException | IOException | CertificateException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchProviderException e){
            e.printStackTrace();
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    private boolean cipherInit(){
        try {
            cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e){
            throw new RuntimeException("Failed to get Cipher", e);
        }
        try {
            keyStore.load(null);
            SecretKey key = (SecretKey) keyStore.getKey(MY_KEY_NAME, null);

            cipher.init(Cipher.ENCRYPT_MODE, key);

            return true;

        } catch (KeyPermanentlyInvalidatedException e) {
            return false;
        } catch (IOException | CertificateException | NoSuchAlgorithmException | UnrecoverableKeyException | InvalidKeyException | KeyStoreException e) {
            throw new RuntimeException("Failed to init Cipher", e);
        }
    }
}
