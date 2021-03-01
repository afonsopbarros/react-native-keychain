package com.oblador.keychain.cipherStorage;

import android.annotation.SuppressLint;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyPermanentlyInvalidatedException;


import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;

import com.oblador.keychain.KeychainModule;
import com.oblador.keychain.SecurityLevel;
import com.oblador.keychain.exceptions.CryptoFailedException;
import com.oblador.keychain.exceptions.KeyStoreAccessException;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.spec.KeySpec;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Fingerprint biometry protected storage.
 */
@RequiresApi(api = Build.VERSION_CODES.M)
@SuppressWarnings({"unused", "WeakerAccess"})
public class CipherStorageKeystoreAesGcmBiometrics extends CipherStorageBase {

  public CipherStorageKeystoreAesGcmBiometrics(boolean isStrongboxAvailable) {
    this.isStrongboxAvailable = isStrongboxAvailable;
  }

  //region Constants
  /** Selected algorithm. */
  public static final String ALGORITHM_AES = KeyProperties.KEY_ALGORITHM_AES;
  /** Selected block mode. */
  public static final String BLOCK_MODE_GCM = KeyProperties.BLOCK_MODE_GCM;
  /** Selected padding transformation. */
  public static final String PADDING_NONE = KeyProperties.ENCRYPTION_PADDING_NONE;
  /** Composed transformation algorithms. */
  public static final String TRANSFORMATION_AES_GCM_NONE =
    ALGORITHM_AES + "/" + BLOCK_MODE_GCM + "/" + PADDING_NONE;
  /** Selected encryption key size. */
  public static final int ENCRYPTION_KEY_SIZE = 256;

  public static final String DEFAULT_SERVICE = "RN_KEYCHAIN_DEFAULT_ALIAS";
  //endregion

  // excerpt from https://github.com/android/security-samples/tree/main/BiometricLoginKotlin
  private Key getOrCreateSecretKey(@NonNull final String safeAlias,
                                   @NonNull final SecurityLevel level)
    throws GeneralSecurityException {
    // If Secretkey was previously created for that keyName, then grab and return it.
    final KeyStore keyStore = getKeyStoreAndLoad(); // Keystore must be loaded before it can be accessed
    final Key key = keyStore.getKey(safeAlias, null);
    if (key != null) {
      return key;
    }

    // if you reach here, then a new SecretKey must be generated for that keyName
    return generateKeyAndStoreUnderAlias(safeAlias, level);
  }

  //region Overrides
  @Override
  @NonNull
  public EncryptionResult encrypt(@NonNull final DecryptionResultHandler handler,
                                  @NonNull final String alias,
                                  @NonNull final String username,
                                  @NonNull final String password,
                                  @NonNull final SecurityLevel level)
    throws GeneralSecurityException {

    throwIfInsufficientLevel(level);

    final String safeAlias = getDefaultAliasIfEmpty(alias, getDefaultAliasServiceName());

    final Key key = getOrCreateSecretKey(safeAlias, level);

    final EncryptContext context =
      new EncryptContext(safeAlias, password, username);

    Cipher cipher = Cipher.getInstance(getEncryptionTransformation());
    try {
      cipher.init(Cipher.ENCRYPT_MODE, key);
    }
    catch (KeyPermanentlyInvalidatedException e) {
      final KeyStore keyStore = getKeyStoreAndLoad();
      keyStore.deleteEntry(safeAlias);
      final Key newKey = getOrCreateSecretKey(safeAlias, level);
      cipher.init(Cipher.ENCRYPT_MODE, newKey);
    }

    handler.askAccessPermissionsEncryption(context, cipher);

    // do the same as `decryptToResult` in `KeychainModule`
    CryptoFailedException.reThrowOnError(handler.getError());

    if (null == handler.getEncryptionResult()) {
      throw new CryptoFailedException("No encryption results. Something deeply wrong!");
    }
    return handler.getEncryptionResult();
  }

  @NonNull
  @Override
  public DecryptionResult decrypt(@NonNull String alias,
                                  @NonNull byte[] username,
                                  @NonNull byte[] password,
                                  @NonNull final SecurityLevel level, byte[] vector)
    throws GeneralSecurityException {

    final NonInteractiveHandler handler = new NonInteractiveHandler();
    decrypt(handler, alias, username, password, level, vector);

    CryptoFailedException.reThrowOnError(handler.getError());

    if (null == handler.getResult()) {
      throw new CryptoFailedException("No decryption results and no error. Something deeply wrong!");
    }

    return handler.getResult();
  }

  @Override
  @SuppressLint("NewApi")
  public void decrypt(@NonNull DecryptionResultHandler handler,
                      @NonNull String alias,
                      @NonNull byte[] username,
                      @NonNull byte[] password,
                      @NonNull final SecurityLevel level,
                      byte[] vector)
    throws GeneralSecurityException {

    throwIfInsufficientLevel(level);

    final String safeAlias = getDefaultAliasIfEmpty(alias, getDefaultAliasServiceName());

    // key is always NOT NULL otherwise GeneralSecurityException raised
    Key key = getOrCreateSecretKey(safeAlias, level);

    final DecryptionContext context =
      new DecryptionContext(safeAlias, key, password, username);

    Cipher cipher = Cipher.getInstance(getEncryptionTransformation());
    cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, vector));

    handler.askAccessPermissions(context, cipher);
  }

  //region Configuration
  @Override
  public String getCipherStorageName() {
    return KeychainModule.KnownCiphers.AES_BIOMETRICS;
  }

  /**
   * API23 is a requirement.
   */
  @Override
  public int getMinSupportedApiLevel() {
    return Build.VERSION_CODES.M;
  }

  /**
   * it can guarantee security levels up to SECURE_HARDWARE/SE/StrongBox
   */
  @Override
  public SecurityLevel securityLevel() {
    return SecurityLevel.SECURE_HARDWARE;
  }

  /**
   * Biometry is Not Supported.
   */
  @Override
  public boolean isBiometrySupported() {
    return true;
  }

  /**
   * AES.
   */
  @Override
  @NonNull
  protected String getEncryptionAlgorithm() {
    return ALGORITHM_AES;
  }

  /**
   * AES/CBC/PKCS7Padding
   */
  @NonNull
  @Override
  protected String getEncryptionTransformation() {
    return TRANSFORMATION_AES_GCM_NONE;
  }

  /**
   * {@inheritDoc}. Override for saving the compatibility with previous version of lib.
   */
  @Override
  public String getDefaultAliasServiceName() {
    return DEFAULT_SERVICE;
  }

  //endregion

  /**
   * Get encryption algorithm specification builder instance.
   */
  @NonNull
  @Override
  protected KeyGenParameterSpec.Builder getKeyGenSpecBuilder(@NonNull final String alias)
    throws GeneralSecurityException {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
      throw new KeyStoreAccessException("Unsupported API" + Build.VERSION.SDK_INT + " version detected.");
    }

    final int purposes = KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT;

    return new KeyGenParameterSpec.Builder(alias, purposes)
      .setBlockModes(BLOCK_MODE_GCM)
      .setEncryptionPaddings(PADDING_NONE)
      .setKeySize(ENCRYPTION_KEY_SIZE)
      .setUserAuthenticationRequired(true);
  }

  /**
   * Get information about provided key.
   */
  @NonNull
  @Override
  protected KeyInfo getKeyInfo(@NonNull final Key key) throws GeneralSecurityException {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
      throw new KeyStoreAccessException("Unsupported API" + Build.VERSION.SDK_INT + " version detected.");
    }

    final SecretKeyFactory factory = SecretKeyFactory.getInstance(key.getAlgorithm(), KEYSTORE_TYPE);
    final KeySpec keySpec = factory.getKeySpec((SecretKey) key, KeyInfo.class);

    return (KeyInfo) keySpec;
  }

  /**
   * Try to generate key from provided specification.
   */
  @NonNull
  @Override
  protected Key generateKey(@NonNull final KeyGenParameterSpec spec) throws GeneralSecurityException {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
      throw new KeyStoreAccessException("Unsupported API" + Build.VERSION.SDK_INT + " version detected.");
    }

    final KeyGenerator generator = KeyGenerator.getInstance(getEncryptionAlgorithm(), KEYSTORE_TYPE);

    // initialize key generator
    generator.init(spec);

    return generator.generateKey();
  }

  //endregion

  //region Nested classes

  /**
   * Non interactive handler for decrypting the credentials.
   */
  public static class NonInteractiveHandler implements DecryptionResultHandler {
    private DecryptionResult result;
    private Throwable error;
    private EncryptionResult encryptionResult;

    @Override
    public void askAccessPermissions(@NonNull final DecryptionContext context, Cipher cipher) {
      final CryptoFailedException failure = new CryptoFailedException(
        "Non interactive decryption mode.");

      onError(failure);
    }

    @Override
    public void onDecrypt(@Nullable DecryptionResult decryptionResult) {
      this.result = decryptionResult;
      this.encryptionResult = null;
      this.error = null;
    }

    @Override
    public void onEncrypt(@Nullable EncryptionResult encryptionResult) {
      this.result = null;
      this.encryptionResult = encryptionResult;
      this.error = null;
    }

    @Override
    public void onError(@Nullable Throwable error) {
      this.result = null;
      this.encryptionResult = null;
      this.error = error;
    }

    @Override
    public void askAccessPermissionsEncryption(@NonNull EncryptContext context, Cipher cipher) {
      final CryptoFailedException failure = new CryptoFailedException(
        "Non interactive encryption mode.");

      onError(failure);
    }

    @Nullable
    @Override
    public DecryptionResult getResult() {
      return result;
    }

    @Nullable
    @Override
    public EncryptionResult getEncryptionResult() {
      return encryptionResult;
    }

    @Nullable
    @Override
    public Throwable getError() {
      return error;
    }

    @Override
    public void waitResult() {
      /* do nothing, expected synchronized call in one thread */
    }
  }
  //endregion
}
