package io.phasetwo.keycloak.resources;

import com.lowagie.text.*;
import com.lowagie.text.pdf.ColumnText;
import com.lowagie.text.pdf.PdfContentByte;
import com.lowagie.text.pdf.PdfPageEventHelper;
import com.lowagie.text.pdf.PdfWriter;
import com.lowagie.text.pdf.draw.LineSeparator;
import lombok.extern.jbosslog.JBossLog;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

@JBossLog
class HeaderFooterPageEvent extends PdfPageEventHelper {
    Font footerFont = FontFactory.getFont(FontFactory.HELVETICA, 10);
    Font footerBold = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 10);
    Image logo;

    public HeaderFooterPageEvent() {
        try {
            // Load the logo from the resources inside the JAR file
            try (InputStream logoStream = getClass().getResourceAsStream("/logo.png")) {
                if (logoStream != null) {
                    // Convert InputStream to byte array
                    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                    byte[] buffer = new byte[1024];
                    int length;
                    while ((length = logoStream.read(buffer)) != -1) {
                        byteArrayOutputStream.write(buffer, 0, length);
                    }
                    byte[] logoBytes = byteArrayOutputStream.toByteArray();

                    // Create the logo image from the byte array
                    logo = Image.getInstance(logoBytes);
                } else {
                    log.warn("Logo file not found in resources.");
                }
            } // Adjust the path based on your package structure
        } catch (Exception e) {
            log.warn("Error loading logo image", e);
        }
    }

    @Override
    public void onEndPage(PdfWriter writer, Document document) {
        PdfContentByte cb = writer.getDirectContent();

        // HEADER
        if (logo != null) {
            logo.scaleToFit(120, 60);
            logo.setAbsolutePosition(document.left(), document.top() + 10);
            try {
                cb.addImage(logo);
            } catch (Exception e) {
                log.warn("Uncaught Sender error", e);
            }
        }

        // FOOTER LINE
        Phrase line = new Phrase(new Chunk(new LineSeparator()));
        ColumnText.showTextAligned(cb, Element.ALIGN_CENTER, line,
                (document.right() + document.left()) / 2, document.bottom() - 10, 0);

        // FOOTER TEXT
        ColumnText.showTextAligned(cb, Element.ALIGN_CENTER,
                new Phrase("Your Company Name Pvt. Ltd.", footerBold),
                (document.right() + document.left()) / 2, document.bottom() - 25, 0);

        ColumnText.showTextAligned(cb, Element.ALIGN_CENTER,
                new Phrase("123 Tech Park, Business Street, Bengaluru, KA 560001, India", footerFont),
                (document.right() + document.left()) / 2, document.bottom() - 37, 0);

        ColumnText.showTextAligned(cb, Element.ALIGN_CENTER,
                new Phrase("LUT U12345KA2020PTC123456 | https://www.intellipins.com", footerFont),
                (document.right() + document.left()) / 2, document.bottom() - 49, 0);
    }
}
