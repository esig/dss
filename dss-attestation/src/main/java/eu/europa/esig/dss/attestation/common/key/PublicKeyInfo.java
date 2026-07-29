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
package eu.europa.esig.dss.attestation.common.key;

import eu.europa.esig.dss.enumerations.EllipticCurve;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;

/**
 * Provider-independent representation of a public key.
 * <p>
 * This model contains the information required to represent a public key
 * independently of a cryptographic provider or serialization format.
 * It can subsequently be transformed into different representations,
 * such as COSE_Key or JWK.
 *
 */
public abstract class PublicKeyInfo implements Serializable {

    private static final long serialVersionUID = 6922363315858043446L;

    /**
     * Default constructor
     */
    protected PublicKeyInfo() {
        // empty
    }

    /**
     * Creates an EC public key representation.
     *
     * @param curve
     *            the elliptic curve
     * @param x
     *            the affine X coordinate
     * @param y
     *            the affine Y coordinate
     * @return an EC public key representation
     */
    public static ECKey ecKey(EllipticCurve curve, byte[] x, byte[] y) {
        return new ECKey(curve, x, y);
    }

    /**
     * Creates an OKP public key representation.
     *
     * @param curve
     *            the elliptic curve
     * @param x
     *            the public key value
     * @return an OKP public key representation
     */
    public static OKPKey okpKey(EllipticCurve curve, byte[] x) {
        return new OKPKey(curve, x);
    }

    /**
     * Creates an RSA public key representation.
     *
     * @param modulus
     *            the RSA modulus
     * @param exponent
     *            the RSA public exponent
     * @return an RSA public key representation
     */
    public static RSAKey rsaKey(byte[] modulus, byte[] exponent) {
        return new RSAKey(modulus, exponent);
    }

    /**
     * Gets the key type identifier.
     *
     * @return the key type identifier
     */
    public abstract String getKeyType();

    /**
     * Representation of an elliptic curve public key.
     */
    public static class ECKey extends PublicKeyInfo {

        private static final long serialVersionUID = 6993201441610999928L;

        /**
         * Elliptic curve associated with the public key.
         */
        private final EllipticCurve curve;

        /**
         * Affine X coordinate of the public key point.
         */
        private final byte[] x;

        /**
         * Affine Y coordinate of the public key point.
         */
        private final byte[] y;

        /**
         * Constructor.
         *
         * @param curve
         *            the elliptic curve
         * @param x
         *            the affine X coordinate
         * @param y
         *            the affine Y coordinate
         */
        protected ECKey(EllipticCurve curve, byte[] x, byte[] y) {
            Objects.requireNonNull(curve, "Curve cannot be null");
            Objects.requireNonNull(x, "X coordinate cannot be null");
            Objects.requireNonNull(y, "Y coordinate cannot be null");

            this.curve = curve;
            this.x = x;
            this.y = y;
        }

        /**
         * Gets the key type identifier.
         *
         * @return {@code EC}
         */
        @Override
        public String getKeyType() {
            return "EC";
        }

        /**
         * Gets the elliptic curve.
         *
         * @return the elliptic curve
         */
        public EllipticCurve getCurve() {
            return curve;
        }

        /**
         * Gets the affine X coordinate.
         *
         * @return the affine X coordinate
         */
        public byte[] getX() {
            return x;
        }

        /**
         * Gets the affine Y coordinate.
         *
         * @return the affine Y coordinate
         */
        public byte[] getY() {
            return y;
        }

        @Override
        public boolean equals(Object object) {
            if (this == object) return true;
            if (object == null || getClass() != object.getClass()) return false;

            ECKey ecKey = (ECKey) object;
            return curve == ecKey.curve
                    && Arrays.equals(x, ecKey.x)
                    && Arrays.equals(y, ecKey.y);
        }

        @Override
        public int hashCode() {
            int result = curve.hashCode();
            result = 31 * result + Arrays.hashCode(x);
            result = 31 * result + Arrays.hashCode(y);
            return result;
        }

    }

    /**
     * Representation of an octet key pair public key.
     */
    public static class OKPKey extends PublicKeyInfo {

        private static final long serialVersionUID = -916875184718455295L;

        /**
         * Elliptic curve associated with the public key.
         */
        private final EllipticCurve curve;

        /**
         * Public key value.
         */
        private final byte[] x;

        /**
         * Constructor.
         *
         * @param curve
         *            the elliptic curve
         * @param x
         *            the public key value
         */
        protected OKPKey(EllipticCurve curve, byte[] x) {
            Objects.requireNonNull(curve, "Curve cannot be null");
            Objects.requireNonNull(x, "X coordinate cannot be null");

            this.curve = curve;
            this.x = x;
        }

        /**
         * Gets the key type identifier.
         *
         * @return {@code OKP}
         */
        @Override
        public String getKeyType() {
            return "OKP";
        }

        /**
         * Gets the elliptic curve.
         *
         * @return the elliptic curve
         */
        public EllipticCurve getCurve() {
            return curve;
        }

        /**
         * Gets the public key value.
         *
         * @return the public key value
         */
        public byte[] getX() {
            return x;
        }

        @Override
        public boolean equals(Object object) {
            if (this == object) return true;
            if (object == null || getClass() != object.getClass()) return false;

            OKPKey okpKey = (OKPKey) object;
            return curve == okpKey.curve
                    && Arrays.equals(x, okpKey.x);
        }

        @Override
        public int hashCode() {
            int result = curve.hashCode();
            result = 31 * result + Arrays.hashCode(x);
            return result;
        }

    }

    /**
     * Representation of an RSA public key.
     */
    public static class RSAKey extends PublicKeyInfo {

        private static final long serialVersionUID = -7856061902202173963L;

        /**
         * RSA modulus.
         */
        private final byte[] modulus;

        /**
         * RSA public exponent.
         */
        private final byte[] exponent;

        /**
         * Constructor.
         *
         * @param modulus
         *            the RSA modulus
         * @param exponent
         *            the RSA public exponent
         */
        protected RSAKey(byte[] modulus, byte[] exponent) {
            Objects.requireNonNull(modulus, "Modulus cannot be null");
            Objects.requireNonNull(exponent, "Exponent cannot be null");

            this.modulus = modulus;
            this.exponent = exponent;
        }

        /**
         * Gets the key type identifier.
         *
         * @return {@code RSA}
         */
        @Override
        public String getKeyType() {
            return "RSA";
        }

        /**
         * Gets the RSA modulus.
         *
         * @return the RSA modulus
         */
        public byte[] getModulus() {
            return modulus;
        }

        /**
         * Gets the RSA public exponent.
         *
         * @return the RSA public exponent
         */
        public byte[] getExponent() {
            return exponent;
        }

        @Override
        public boolean equals(Object object) {
            if (this == object) return true;
            if (object == null || getClass() != object.getClass()) return false;

            RSAKey rsaKey = (RSAKey) object;
            return Arrays.equals(modulus, rsaKey.modulus)
                    && Arrays.equals(exponent, rsaKey.exponent);
        }

        @Override
        public int hashCode() {
            int result = Arrays.hashCode(modulus);
            result = 31 * result + Arrays.hashCode(exponent);
            return result;
        }

    }

}