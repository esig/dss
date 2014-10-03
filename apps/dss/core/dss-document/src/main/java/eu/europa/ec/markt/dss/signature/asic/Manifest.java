package eu.europa.ec.markt.dss.signature.asic;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.OutputStream;

/**
 * Represents the META-INF/manifest.xml subdocument
 */
public class Manifest {

  private Document dom;
  private final Logger logger = LoggerFactory.getLogger(Manifest.class);
  private Element rootElement;

  /**
   * creates object to create manifest files
   */
  public Manifest() {
    logger.debug("");
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    try {
      DocumentBuilder db = dbf.newDocumentBuilder();

      dom = db.newDocument();
      rootElement = dom.createElement("manifest:manifest");
      rootElement.setAttribute("xmlns:manifest", "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0");

      Element firstChild = dom.createElement("manifest:file-entry");
      firstChild.setAttribute("manifest:full-path", "/");
      firstChild.setAttribute("manifest:media-type", "application/vnd.etsi.asic-e+zip");
      rootElement.appendChild(firstChild);

      dom.appendChild(rootElement);

    } catch (ParserConfigurationException e) {
      logger.error(e.getMessage());
      throw new DSSException(e);
    }
  }

  /**
   * adds list of attachments to create manifest file
   *
   * @param document list of data files
   */
  public void addFileEntry(DSSDocument document) {
    Element childElement;
    DSSDocument entry = document;
    do  {
      childElement = dom.createElement("manifest:file-entry");
      childElement.setAttribute("manifest:media-type", entry.getMimeType().getCode());
      childElement.setAttribute("manifest:full-path", entry.getName());
      rootElement.appendChild(childElement);
      logger.debug("adds " + entry.getName() + " to manifest");
      entry = entry.getNextDocument();
    } while (entry != null);

  }

  /**
   * sends manifest files to output stream
   *
   * @param out output stream
   */
  public void save(OutputStream out) {
    DOMImplementationLS implementation = (DOMImplementationLS) dom.getImplementation();
    LSOutput lsOutput = implementation.createLSOutput();
    lsOutput.setByteStream(out);
    LSSerializer writer = implementation.createLSSerializer();
    writer.write(dom, lsOutput);
  }
}
