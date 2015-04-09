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
package eu.europa.esig.dss.x509;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class TokenValidationExtraInfo implements Serializable{

   /*
    * This is the list of text messages created during the signature validation process. It allows to get more
    * information about different problems encountered during the curse of this process.
    */
   protected ArrayList<String> validationInfo = new ArrayList<String>();

   public void infoTheSigningCertNotFound() {

      validationInfo.add("The certificate used to sign this token is not found or not valid!");
   }

   public void add(String message) {

      validationInfo.add(message);
   }

   /**
    * Returns the additional information gathered during the validation process.
    * 
    * @return
    */
   public List<String> getValidationInfo() {

      return Collections.unmodifiableList(validationInfo);
   }

}
