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
package eu.europa.ec.markt.dss.validation102853.toolbox;

import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;

public class Reversed<T> implements Iterable<T> {
   private final List<T> original;

   public Reversed(List<T> original) {
      this.original = original;
   }

   public Iterator<T> iterator() {
      
      final ListIterator<T> i = original.listIterator(original.size());

      return new Iterator<T>() {
         public boolean hasNext() {
            return i.hasPrevious();
         }

         public T next() {
            return i.previous();
         }

         public void remove() {
            i.remove();
         }
      };
   }

   public static <T> Reversed<T> reversed(List<T> original) {
      return new Reversed<T>(original);
   }
}