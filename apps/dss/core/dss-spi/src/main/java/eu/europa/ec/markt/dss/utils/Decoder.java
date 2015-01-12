/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package eu.europa.ec.markt.dss.utils;

import eu.europa.ec.markt.dss.exception.DSSException;

/**
 * <p>Provides the highest level of abstraction for Decoders.
 * This is the sister interface of {@link eu.europa.ec.markt.dss.utils.Encoder}.  All
 * Decoders implement this common generic interface.</p>
 * <p/>
 * <p>Allows a user to pass a generic Object to any Decoder
 * implementation in the codec package.</p>
 * <p/>
 * <p>One of the two interfaces at the center of the codec package.</p>
 *
 * @author Apache Software Foundation
 * @version $Id: Decoder.java 1157192 2011-08-12 17:27:38Z ggregory $
 */
public interface Decoder {

	/**
	 * Decodes an "encoded" Object and returns a "decoded"
	 * Object.  Note that the implementation of this
	 * interface will try to cast the Object parameter
	 * to the specific type expected by a particular Decoder
	 * implementation.  If a {@link ClassCastException} occurs
	 * this decode method will throw a DecoderException.
	 *
	 * @param source the object to decode
	 * @return a 'decoded" object
	 * @throws DSSException a decoder exception can be thrown for any number of reasons.  Some good candidates are that the parameter passed to this method is null, a param cannot
	 *                      be cast to the appropriate type for a specific encoder.
	 */
	Object decode(Object source) throws DSSException;
}  

