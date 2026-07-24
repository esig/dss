/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.attestation.mdoc;

import eu.europa.esig.dss.cbades.COSEConstants;
import eu.europa.esig.dss.attestation.mdoc.claim.MdocClaimDeviceKey;
import eu.europa.esig.dss.enumerations.EllipticCurve;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.attestation.claim.Claim;
import eu.europa.esig.dss.model.attestation.claim.ClaimByteString;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Objects;

/**
 * This class is used to parse a CBOR_Key representation and returns an extracted information
 *
 */
public abstract class COSEKeyParser {

    /** Mdoc claim to be parser */
    protected final MdocClaimDeviceKey coseKey;

    /**
     * Default constructor
     *
     * @param coseKey {@link MdocClaimDeviceKey}
     */
    protected COSEKeyParser(final MdocClaimDeviceKey coseKey) {
        this.coseKey = coseKey;
    }

    /**
     * Parses the {@code PublicKey} from the ptovided claim
     *
     * @return {@link PublicKey}
     */
    public abstract PublicKey parse();

    /**
     * Gets the elliptic curve from the 'crv' claim
     *
     * @param crv {@link Claim}
     * @return {@link EllipticCurve}
     */
    protected EllipticCurve getEllipticCurve(Claim crv) {
        if (crv.isNumberValueType()) {
            return EllipticCurve.forCOSEValue(crv.getNumberValue());
        } else if (crv.isStringValueType()) {
            return EllipticCurve.forLabel(crv.getStringValue());
        } else {
            throw new UnsupportedOperationException(String.format("The 'crv' of type '%s' is not supported!", crv.getClass().getSimpleName()));
        }
    }

    /**
     * Gets BigInteger from the bytes
     *
     * @param bytes byte array
     * @return {@link BigInteger}
     */
    protected BigInteger fromBytes(byte[] bytes) {
        return new BigInteger(1, bytes);
    }

    /**
     * Gets the applicable parser to read the key content
     *
     * @param coseKey {@link MdocClaimDeviceKey} to be parsed
     * @return {@link COSEKeyParser}
     */
    public static COSEKeyParser from(MdocClaimDeviceKey coseKey) {
        Claim kty = coseKey.getKTY();
        if (kty == null) {
            throw new IllegalInputException("No 'kty' CBOR_KEY header found!");
        }

        if (Objects.equals(COSEConstants.COSE_KEY_TYPE_OKP_NAME, kty.getStringValue()) ||
                (kty.getNumberValue() != null && Objects.equals(COSEConstants.COSE_KEY_TYPE_OKP_VALUE, kty.getNumberValue().longValue()))) {
            return new OKRKeyParser(coseKey);

        } else if (Objects.equals(COSEConstants.COSE_KEY_TYPE_EC2_NAME, kty.getStringValue()) ||
                (kty.getNumberValue() != null && Objects.equals(COSEConstants.COSE_KEY_TYPE_EC2_VALUE, kty.getNumberValue().longValue()))) {
            return new EC2KeyParser(coseKey);

        } else if (Objects.equals(COSEConstants.COSE_KEY_TYPE_RSA_NAME, kty.getStringValue()) ||
                (kty.getNumberValue() != null && Objects.equals(COSEConstants.COSE_KEY_TYPE_RSA_VALUE, kty.getNumberValue().longValue()))) {
            return new RSAKeyParser(coseKey);

        } else {
            throw new UnsupportedOperationException(String.format("CBOR_Key type '%s' is not supported!", kty.getValueAsString()));
        }
    }

    /**
     * Parses an EdDSA public key
     */
    private static class OKRKeyParser extends COSEKeyParser {

        /**
         * Default constructor
         */
        public OKRKeyParser(final MdocClaimDeviceKey coseKey) {
            super(coseKey);
        }

        @Override
        public PublicKey parse() {
            Claim crv = coseKey.get(COSEConstants.COSE_KEY_TYPE_OKP_CRV);
            if (crv == null) {
                throw new NullPointerException("No 'crv' claim is found for the OKR public key!");
            }
            EllipticCurve ellipticCurve = getEllipticCurve(crv);
            if (ellipticCurve == null) {
                throw new UnsupportedOperationException("Elliptic curve cannot be identified or not supported!");
            }

            ClaimByteString x = coseKey.getAsByteString(COSEConstants.COSE_KEY_TYPE_OKP_X);
            if (x == null) {
                throw new NullPointerException("No 'x' claim is found for the EC2 public key!");
            }
            byte[] keyBytes = x.getBinaryValue();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(new ASN1ObjectIdentifier(ellipticCurve.getOID()));

            try {
                switch (ellipticCurve) {
                    case X25519:
                        return new KeyFactorySpi.X25519().generatePublic(new SubjectPublicKeyInfo(algorithmIdentifier, keyBytes));
                    case X448:
                        return new KeyFactorySpi.X448().generatePublic(new SubjectPublicKeyInfo(algorithmIdentifier, keyBytes));
                    case ED25519:
                        return new KeyFactorySpi.Ed25519().generatePublic(new SubjectPublicKeyInfo(algorithmIdentifier, keyBytes));
                    case ED448:
                        return new KeyFactorySpi.Ed448().generatePublic(new SubjectPublicKeyInfo(algorithmIdentifier, keyBytes));
                    default:
                        throw new UnsupportedOperationException(String.format("The OKR key of type '%s' is not supported!", ellipticCurve));
                }

            } catch (IOException e) {
                throw new DSSException(String.format("Unable to read the key : %s", e.getMessage()), e);
            }
        }

    }

    /**
     * Parses an EC public key
     */
    private static class EC2KeyParser extends COSEKeyParser {

        /**
         * Default constructor
         */
        public EC2KeyParser(final MdocClaimDeviceKey coseKey) {
            super(coseKey);
        }

        @Override
        public PublicKey parse() {
            Claim crv = coseKey.get(COSEConstants.COSE_KEY_TYPE_EC2_CRV);
            if (crv == null) {
                throw new NullPointerException("No 'crv' claim is found for the EC2 public key!");
            }
            EllipticCurve ellipticCurve = getEllipticCurve(crv);
            if (ellipticCurve == null) {
                throw new UnsupportedOperationException("Elliptic curve cannot be identified or not supported!");
            }

            ClaimByteString x = coseKey.getAsByteString(COSEConstants.COSE_KEY_TYPE_EC2_X);
            if (x == null) {
                throw new NullPointerException("No 'x' claim is found for the EC2 public key!");
            }
            BigInteger xInt = fromBytes(x.getBinaryValue());

            ClaimByteString y = coseKey.getAsByteString(COSEConstants.COSE_KEY_TYPE_EC2_Y);
            if (y == null) {
                throw new NullPointerException("No 'y' claim is found for the EC2 public key!");
            }
            BigInteger yInt = fromBytes(y.getBinaryValue());

            ECPoint w = new ECPoint(xInt, yInt);
            ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(w, ellipticCurve.getParameter());

            try {
                return KeyFactory.getInstance("EC").generatePublic(ecPublicKeySpec);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new DSSException(String.format("Unable to read the key : %s", e.getMessage()), e);
            }

        }

    }

    /**
     * Parses an RSA public key
     */
    private static class RSAKeyParser extends COSEKeyParser {

        /**
         * Default constructor
         */
        public RSAKeyParser(final MdocClaimDeviceKey coseKey) {
            super(coseKey);
        }

        @Override
        public PublicKey parse() {
            ClaimByteString modulus = coseKey.getAsByteString(COSEConstants.COSE_KEY_TYPE_RSA_N);
            if (modulus == null) {
                throw new NullPointerException("No 'n' (modulus) claim is found for the RSA public key!");
            }
            ClaimByteString exponent = coseKey.getAsByteString(COSEConstants.COSE_KEY_TYPE_RSA_E);
            if (exponent == null) {
                throw new NullPointerException("No 'e' (exponent) claim is found for the RSA public key!");
            }

            RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(fromBytes(modulus.getBinaryValue()), fromBytes(exponent.getBinaryValue()));

            try {
                return KeyFactory.getInstance("RSA").generatePublic(rsaPublicKeySpec);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new DSSException(String.format("Unable to read the key : %s", e.getMessage()), e);
            }

        }

    }

}
