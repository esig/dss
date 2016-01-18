/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.policy;

public class TLQualification {

   int caqc = 0;
   int qcWithSSCD = 0;
   int qcCNoSSCD = 0;
   int qcSSCDAsInCert = 0;
   int qcForLegalPerson = 0;

   public int getCaqc() {
      return caqc;
   }

   public void setCaqc(boolean caqc) {
      this.caqc = caqc ? 1 : 0;
   }

   public int getQcWithSSCD() {
      return qcWithSSCD;
   }

   public void setQcWithSSCD(boolean qcWithSSCD) {
      this.qcWithSSCD = qcWithSSCD ? 1 : 0;
   }

   public int getQcCNoSSCD() {
      return qcCNoSSCD;
   }

   public void setQcCNoSSCD(boolean qcCNoSSCD) {
      this.qcCNoSSCD = qcCNoSSCD ? 1 : 0;
   }

   public int getQcSSCDAsInCert() {
      return qcSSCDAsInCert;
   }

   public void setQcSSCDAsInCert(boolean qcSSCDAsInCert) {
      this.qcSSCDAsInCert = qcSSCDAsInCert ? 1 : 0;
   }

   public int getQcForLegalPerson() {
      return qcForLegalPerson;
   }

   public void setQcForLegalPerson(boolean qcForLegalPerson) {
      this.qcForLegalPerson = qcForLegalPerson ? 1 : 0;
   }
}
