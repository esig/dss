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
package eu.europa.esig.dss.pdf.visible;

import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pdf.AnnotationBox;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Utility class to fit arbitrary text into a text box.
 */
public final class TextFitter {

	/**
	 * The coefficient is used for text height/width calculation in order to reduce impact
	 * of a padding applied by different implementations
	 */
	private static final int FONT_SIZE_COEFFICIENT = 32;

	/**
	 * Empty constructor
	 */
	private TextFitter() {
	}

	/**
	 * Attempts to fit the given {@code text} in the given {@code textBox}
	 * using {@code metrics} to estimate the text size. Existing line breaks
	 * in {@code text} will be maintained.
	 *
	 * @param textParameters {@link SignatureImageTextParameters} containing the text to fit
	 * @param properTextSize the computed text size
	 * @param fontMetrics the font metrics to estimate text size
	 * @param textBox the box into which to fit the text
	 * @return the fitting operation result
	 */
	public static Result fitSignatureText(final SignatureImageTextParameters textParameters, final float properTextSize,
								   final DSSFontMetrics fontMetrics, final AnnotationBox textBox) {
		List<String> lines = Arrays.asList(fontMetrics.getLines(textParameters.getText()));
		if (Utils.isCollectionEmpty(lines)) {
			throw new IllegalArgumentException("No text has been provided!");
		}
		switch (textParameters.getTextWrapping()) {
			case FILL_BOX:
				float fontSize = getMaxPossibleFontSize(textBox, lines, fontMetrics);
				return new Result(fontSize, textParameters.getText());
			case FILL_BOX_AND_LINEBREAK:
				return getBestMaxFontSize(textBox, lines, fontMetrics);
			case FONT_BASED:
				return new Result(properTextSize, textParameters.getText());
			default:
				throw new IllegalArgumentException(String.format("The TextWrapping '%s' is not supported!",
						textParameters.getTextWrapping()));
		}
	}

	/**
	 * Calculates the maximum possible font size that will allow
	 * {@code lineCount} lines to fit in the given {@code height} using
	 * {@code metrics} to estimate line height.
	 *
	 * @param textBox the box to be used to wrap the text
	 * @param lines the text lines to draw
	 * @param fontMetrics the font metrics to estimate line heights
	 * @return the maximum font size that will fit {@code height}
	 */
	private static float getMaxPossibleFontSize(final AnnotationBox textBox, final List<String> lines, final DSSFontMetrics fontMetrics) {
		float maxFontSizeByHeight = getMaxFontSizeByHeight(textBox.getHeight(), lines, fontMetrics);
		float maxFontSizeByWidth = getMaxFontSizeByWidth(textBox.getWidth(), lines, fontMetrics);
		return Math.min(maxFontSizeByHeight, maxFontSizeByWidth);
	}

	private static float getMaxFontSizeByHeight(float textBoxHeight, final List<String> lines, final DSSFontMetrics fontMetrics) {
		float maxLineHeight = textBoxHeight / lines.size();
		// NOTE : 32 used to obtain a more equal result between different implementations (some use a padding for calculated height)
		return maxLineHeight / (fontMetrics.getHeight(lines.iterator().next(), FONT_SIZE_COEFFICIENT) / FONT_SIZE_COEFFICIENT);
	}

	private static float getMaxFontSizeByWidth(float textBoxWidth, final List<String> lines, final DSSFontMetrics fontMetrics) {
		float longestLineWidth = getLongestLineWidth(lines, fontMetrics);
		return textBoxWidth / longestLineWidth;
	}

	private static float getLongestLineWidth(final List<String> lines, final DSSFontMetrics fontMetrics) {
		float longestLineWidth = -1;
		for (String line : lines) {
			float lineWidth = fontMetrics.getWidth(line, FONT_SIZE_COEFFICIENT) / FONT_SIZE_COEFFICIENT;
			if (lineWidth > longestLineWidth) {
				longestLineWidth = lineWidth;
			}
		}
		return longestLineWidth;
	}

	private static Result getBestMaxFontSize(final AnnotationBox textBox, final List<String> lines, final DSSFontMetrics fontMetrics) {
		final StringBuilder sb = new StringBuilder(); // use a single instance for performance reasons
		List<String> wrappedLines = lines;
		float maxFontSizeByHeight = getMaxFontSizeByHeight(textBox.getHeight(), wrappedLines, fontMetrics);
		float maxFontSizeByWidth = getMaxFontSizeByWidth(textBox.getWidth(), wrappedLines, fontMetrics);
		if (maxFontSizeByHeight > maxFontSizeByWidth) {
			int maxPossibleLinesNumber = getMaxPossibleLinesNumber(lines);
			for (int ii = 0; ii < maxPossibleLinesNumber - lines.size() && maxFontSizeByWidth <= maxFontSizeByHeight; ii++) {
				final List<String> newLines = wrapLineWithMetrics(lines, fontMetrics, sb,
						maxFontSizeByHeight, textBox.getWidth(), ii + 1);

				wrappedLines = newLines;
				float newFontSizeByHeight = getMaxFontSizeByHeight(textBox.getHeight(), newLines, fontMetrics);
				float newFontSizeByWidth = getMaxFontSizeByWidth(textBox.getWidth(), newLines, fontMetrics);
				if (maxFontSizeByHeight == newFontSizeByHeight || maxFontSizeByWidth == newFontSizeByWidth) {
					// unable to decrease
					if (maxFontSizeByHeight > maxFontSizeByWidth) {
						maxFontSizeByHeight = newFontSizeByWidth;
					} else {
						break;
					}
				} else {
					maxFontSizeByHeight = newFontSizeByHeight;
					maxFontSizeByWidth = newFontSizeByWidth;
				}
			}
		}
		float computedFontSize = Math.min(maxFontSizeByHeight, maxFontSizeByWidth);
		String joinedText = Utils.joinStrings(wrappedLines, "\n");
		return new Result(computedFontSize, joinedText);
	}

	private static int getMaxPossibleLinesNumber(final List<String> lines) {
		int maxLinesNumber = 0;
		for (String line : lines) {
			String[] words = line.split(" ");
			maxLinesNumber += words.length;
		}
		return maxLinesNumber;
	}

	private static List<String> wrapLineWithMetrics(final List<String> lines, final DSSFontMetrics fontMetrics,
													final StringBuilder sb, final float fontSize, final float maxWidth,
													int linesToAdd) {
		List<String> result = lines;

		for (int ii = 0; ii < linesToAdd; ii++) {
			final List<String> wrappedLines = new ArrayList<>();

			String longestLineToDivide = null;
			float longestLineWidth = -1;
			for (String line : result) {
				float lineWidth = fontMetrics.getWidth(line, FONT_SIZE_COEFFICIENT);
				if (maxWidth < lineWidth && longestLineWidth < lineWidth) {
					longestLineToDivide = line;
					longestLineWidth = lineWidth;
				}
			}

			if (longestLineToDivide == null) {
				return result;
			}

			for (String line : result) {
				if (longestLineToDivide.equals(line)) {
					String[] words = line.split(" ");
					int firstWord = 0;

					for (int lastWord = words.length - 1; lastWord >= firstWord; lastWord--) {
						String stringToAdd = null;
						if (lastWord == firstWord) {
							stringToAdd = words[firstWord];
							firstWord = lastWord + 1;

						} else {
							for (int j = firstWord; j <= lastWord; j++) {
								if (j > firstWord) {
									sb.append(' ');
								}
								String word = words[j];
								sb.append(word);
							}

							String substring = sb.toString();
							if (fontMetrics.getWidth(substring, fontSize) <= maxWidth) {
								stringToAdd = substring;
							}
							sb.setLength(0); // clean the buffer
						}

						if (Utils.isStringNotEmpty(stringToAdd)) {
							wrappedLines.add(stringToAdd);

							for (int j = lastWord + 1; j < words.length; j++) {
								if (j > lastWord + 1) {
									sb.append(' ');
								}
								String word = words[j];
								sb.append(word);
							}

							String substringAfter = sb.toString();
							if (Utils.isStringNotEmpty(substringAfter)) {
								wrappedLines.add(substringAfter);
							}
							sb.setLength(0); // clean the buffer
							break;
						}
					}

				} else {
					wrappedLines.add(line);
				}
			}
			result = wrappedLines;
		}

		return result;
	}

	/**
	 * The result of a text fitting operation.
	 */
	public static final class Result {

		/** The calculated font size */
		private final float size;

		/** The computed text */
		private final String text;

		/**
		 * Default constructor
		 *
		 * @param size font size
		 * @param text {@link String}
		 */
		private Result(float size, String text) {
			this.size = size;
			this.text = text;
		}

		/**
		 * Returns the calculated font size.
		 *
		 * @return the calculated font size
		 */
		public float getSize() {
			return size;
		}

		/**
		 * Returns the fitted text.
		 *
		 * @return the fitted text
		 */
		public String getText() {
			return text;
		}

	}

}
