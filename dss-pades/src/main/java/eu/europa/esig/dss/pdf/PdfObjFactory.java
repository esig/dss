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
package eu.europa.esig.dss.pdf;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import eu.europa.esig.dss.pdf.pdfbox.PdfBoxObjectFactory;

/**
 * The usage of this interface permit the user to choose the underlying PDF library use to created PDF signatures.
 * 
 * 
 *
 */
public abstract class PdfObjFactory {

   private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(PdfObjFactory.class.getName());

   private static PdfObjFactory INSTANCE;

   public static PdfObjFactory getInstance() {
      if (INSTANCE == null) {
         String factoryClassName = System.getProperty("dss.pdf_obj_factory");
         if (factoryClassName != null) {
            LOGGER.info("Using '" + factoryClassName + "' as the PDF Object Factory Implementation");
            try {
               @SuppressWarnings("unchecked")
               Class<PdfObjFactory> factoryClass = (Class<PdfObjFactory>) Class.forName(factoryClassName);
               INSTANCE = factoryClass.newInstance();
            } catch (Exception ex) {
               LOGGER.error("dss.pdf_obj_factory is '" + factoryClassName + "' but factory cannot be instantiated (fallback will be used)");
            }
         }
         if (INSTANCE == null) {
            LOGGER.info("Fallback to '" + PdfBoxObjectFactory.class.getName() + "' as the PDF Object Factory Implementation");
            INSTANCE = new PdfBoxObjectFactory();
         }
      }
      return INSTANCE;
   }

   public abstract PdfArray newArray();

   public abstract PdfDict newDict(String dictType);

   public PdfDict newDict() {
      return newDict(null);
   }

   public abstract PdfReader newReader(InputStream input) throws IOException;

   public abstract PdfStream newStream(byte[] bytes) throws IOException;

   public abstract PdfWriter newWriter(PdfReader reader, OutputStream output) throws IOException;

   public abstract PDFSignatureService newPAdESSignatureService();

   public abstract PDFTimestampService newTimestampSignatureService();

}
