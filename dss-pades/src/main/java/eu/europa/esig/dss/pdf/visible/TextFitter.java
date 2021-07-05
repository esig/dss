package eu.europa.esig.dss.pdf.visible;

import eu.europa.esig.dss.pdf.AnnotationBox;
import java.util.ArrayList;
import java.util.List;

/**
 * Utility class to fit arbitrary text into a text box.
 */
public final class TextFitter {

	private static final int DEFAULT_MAX_EXTRA_LINES = 15;
	private static final boolean DEFAULT_ALLOW_SINGLE_WORD_OVERFLOW = false;

	/**
	 * The maximum number of new lines the may be added during the fitting.
	 */
	private final int maxExtraLines;

	/**
	 * If the text fitter should accept lines that overflow out of the text
	 * box when they contain only one word.
	 */
	private final boolean allowSWOverflow;

	/**
	 * Creates a new text fitter with default configuration.
	 */
	public TextFitter() {
		this(DEFAULT_MAX_EXTRA_LINES, DEFAULT_ALLOW_SINGLE_WORD_OVERFLOW);
	}

	/**
	 * Creates a new text fitter with the given options.
	 *
	 * @param maxExtraLines the maximum number of extra lines
	 * @param allowSWOverflow if single word overflow is allowed
	 */
	public TextFitter(int maxExtraLines, boolean allowSWOverflow) {
		this.maxExtraLines = maxExtraLines;
		this.allowSWOverflow = allowSWOverflow;
	}

	/**
	 * Attempts to fit the given {@code text} in the given {@code textBox}
	 * using {@code metrics} to estimate the text size. Existing line breaks
	 * in {@code text} will be maintained.
	 *
	 * @param text the text to fit
	 * @param fontMetrics the font metrics to estimate text size
	 * @param textBox the box into which to fit the text
	 * @return the fitting operation result
	 */
	public Result fitSignatureText(final String text, final DSSFontMetrics fontMetrics, final AnnotationBox textBox) {
		String[] lines = fontMetrics.getLines(text);
		return fitSignatureText(lines, fontMetrics, textBox);
	}

	/**
	 * Attempts to fit the given {@code lines} of text in the given
	 * {@code textBox} using {@code metrics} to estimate the text size.
	 *
	 * @param lines the text lines to fit, lines should not contain line
	 * breaks
	 * @param fontMetrics the font metrics to estimate text size
	 * @param textBox the box into which to fit the text
	 * @return the fitting operation result
	 */
	public Result fitSignatureText(final String[] lines, final DSSFontMetrics fontMetrics, final AnnotationBox textBox) {
		for (int targetLineCount = lines.length; targetLineCount <= lines.length + maxExtraLines; targetLineCount++) {
			float fontSize = getMaxFontSize(textBox.getHeight(), targetLineCount, fontMetrics);
			final ArrayList<String> wrappedLines = new ArrayList<>(targetLineCount);
			boolean linesFit = wrapLinesWithMetrics(lines, wrappedLines, fontMetrics, fontSize, textBox.getWidth(), targetLineCount);

			if (linesFit) {
				String joinedText = String.join("\n", wrappedLines);
				return new Result(fontSize, joinedText);
			}
		}

		return new Result();
	}

	/**
	 * Calculates the maximum possible font size that will allow
	 * {@code lineCount} lines to fit in the given {@code height} using
	 * {@code metrics} to estimate line height.
	 *
	 * @param height the height to fit the text lines in
	 * @param lineCount the number of text lines to fit
	 * @param fontMetrics the font metrics to estimate line heights
	 * @return the maximum font size that will fit {@code height}
	 */
	private float getMaxFontSize(final float height, final int lineCount, final DSSFontMetrics fontMetrics) {
		float maxLineHeight = height / lineCount;
		return maxLineHeight / fontMetrics.getHeight("X", 1);
	}

	private boolean wrapLinesWithMetrics(final String[] lines, final List<String> wrappedLines, final DSSFontMetrics fontMetrics, float fontSize, float maxWidth, int maxLines) {
		StringBuilder sb = new StringBuilder();

		for (String line : lines) {
			if (!wrapLineWithMetrics(wrappedLines, line, fontMetrics, fontSize, maxWidth, sb, maxLines)) {
				return false;
			}
		}

		return true;
	}

	private boolean wrapLineWithMetrics(final List<String> wrappedLines, final String line,
		final DSSFontMetrics fontMetrics, final float fontSize, final float maxWidth,
		final StringBuilder sb, final int maxLines) {
		String[] words = line.split(" ");
		int firstWord = 0;

		while (firstWord < words.length) {
			for (int lastWord = words.length - 1; lastWord >= firstWord; lastWord--) {
				if (wrappedLines.size() >= maxLines) {
					return false;
				}

				if (lastWord == firstWord) {
					if (allowSWOverflow || fontMetrics.getWidth(words[firstWord], fontSize) <= maxWidth) {
						wrappedLines.add(words[firstWord]);
						firstWord = lastWord + 1;
					} else {
						return false;
					}
				} else {
					for (int j = firstWord; j <= lastWord; j++) {
						if (j > firstWord) {
							sb.append(' ');
						}
						String word = words[j];
						sb.append(word);
					}
					String substring = sb.toString();
					sb.delete(0, sb.length());

					if (fontMetrics.getWidth(substring, fontSize) <= maxWidth) {
						wrappedLines.add(substring);
						firstWord = lastWord + 1;
						break;
					}
				}
			}
		}

		return true;
	}

	/**
	 * The result of a text fitting operation.
	 */
	public static final class Result {

		private final boolean fitted;
		private final float size;
		private final String text;

		private Result() {
			this.fitted = false;
			this.size = -1;
			this.text = null;
		}

		private Result(float size, String text) {
			this.fitted = true;
			this.size = size;
			this.text = text;
		}

		/**
		 * Returns the operation status.
		 *
		 * @return {@code true} if the operation finished successfully
		 */
		public boolean isFitted() {
			return fitted;
		}

		/**
		 * Returns the calculated font size. Value has no meaning if
		 * {@link #isFitted()} yields {@code false}.
		 *
		 * @return the calculated font size
		 */
		public float getSize() {
			return size;
		}

		/**
		 * Returns the fitted text. Value has no meaning if
		 * {@link #isFitted()} yields {@code false}.
		 *
		 * @return the fitted text
		 */
		public String getText() {
			return text;
		}

	}

}
