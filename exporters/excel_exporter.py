import os
import json
import html


def generate_excel_xml_report(output_dir, sheets_data, filename="forensic_report.xls"):
    """
    Generates a multi-sheet Microsoft Excel Workbook (XML Spreadsheet 2003 format)
    containing separate styled worksheets for every collected forensic module.
    Natively opens in Microsoft Excel, LibreOffice, and Google Sheets without external dependencies.
    """
    xml_parts = []
    xml_parts.append('<?xml version="1.0" encoding="UTF-8"?>')
    xml_parts.append('<?mso-application progid="Excel.Sheet"?>')
    xml_parts.append('<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet"')
    xml_parts.append(' xmlns:o="urn:schemas-microsoft-com:office:office"')
    xml_parts.append(' xmlns:x="urn:schemas-microsoft-com:office:excel"')
    xml_parts.append(' xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet"')
    xml_parts.append(' xmlns:html="http://www.w3.org/TR/REC-html40">')

    # Styles
    xml_parts.append('<Styles>')
    xml_parts.append(' <Style ss:ID="Default" ss:Name="Normal">')
    xml_parts.append('  <Alignment ss:Vertical="Center"/>')
    xml_parts.append('  <Font ss:FontName="Segoe UI" ss:Size="10" ss:Color="#000000"/>')
    xml_parts.append(' </Style>')
    xml_parts.append(' <Style ss:ID="HeaderStyle">')
    xml_parts.append('  <Alignment ss:Vertical="Center" ss:Horizontal="Left"/>')
    xml_parts.append('  <Font ss:FontName="Segoe UI" ss:Size="11" ss:Bold="1" ss:Color="#FFFFFF"/>')
    xml_parts.append('  <Interior ss:Color="#1E293B" ss:Pattern="Solid"/>')
    xml_parts.append(' </Style>')
    xml_parts.append(' <Style ss:ID="TitleStyle">')
    xml_parts.append('  <Alignment ss:Vertical="Center" ss:Horizontal="Left"/>')
    xml_parts.append('  <Font ss:FontName="Segoe UI" ss:Size="14" ss:Bold="1" ss:Color="#0891B2"/>')
    xml_parts.append(' </Style>')
    xml_parts.append(' <Style ss:ID="WarningStyle">')
    xml_parts.append('  <Font ss:FontName="Segoe UI" ss:Size="10" ss:Bold="1" ss:Color="#DC2626"/>')
    xml_parts.append('  <Interior ss:Color="#FEE2E2" ss:Pattern="Solid"/>')
    xml_parts.append(' </Style>')
    xml_parts.append('</Styles>')

    for sheet_name, rows in sheets_data.items():
        clean_sheet_name = "".join(c for c in sheet_name if c.isalnum() or c in (" ", "_", "-"))[:30]
        xml_parts.append(f'<Worksheet ss:Name="{html.escape(clean_sheet_name)}">')
        xml_parts.append('<Table>')

        if not rows:
            xml_parts.append('<Row><Cell><Data ss:Type="String">No records collected for this category.</Data></Cell></Row>')
            xml_parts.append('</Table></Worksheet>')
            continue

        if isinstance(rows, list) and len(rows) > 0 and isinstance(rows[0], dict):
            # Extract headers
            cols = [k for k in rows[0].keys() if not isinstance(rows[0][k], (dict, list))]
            
            # Header row
            xml_parts.append('<Row ss:Height="24">')
            for col in cols:
                xml_parts.append(f'<Cell ss:StyleID="HeaderStyle"><Data ss:Type="String">{html.escape(str(col))}</Data></Cell>')
            xml_parts.append('</Row>')

            # Data rows
            for r in rows:
                xml_parts.append('<Row>')
                for col in cols:
                    val = r.get(col, "")
                    val_str = str(val) if val is not None else ""
                    
                    is_suspicious = (col == "is_suspicious" and val is True) or (col == "severity" and str(val).lower() in ["critical", "high"])
                    style_attr = ' ss:StyleID="WarningStyle"' if is_suspicious else ""
                    
                    xml_parts.append(f'<Cell{style_attr}><Data ss:Type="String">{html.escape(val_str)}</Data></Cell>')
                xml_parts.append('</Row>')

        elif isinstance(rows, dict):
            # Key-value sheet
            xml_parts.append('<Row ss:Height="22"><Cell ss:StyleID="HeaderStyle"><Data ss:Type="String">Property</Data></Cell><Cell ss:StyleID="HeaderStyle"><Data ss:Type="String">Value</Data></Cell></Row>')
            for k, v in rows.items():
                val_str = json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else str(v)
                xml_parts.append(f'<Row><Cell><Data ss:Type="String">{html.escape(str(k))}</Data></Cell><Cell><Data ss:Type="String">{html.escape(val_str)}</Data></Cell></Row>')

        xml_parts.append('</Table>')
        xml_parts.append('</Worksheet>')

    xml_parts.append('</Workbook>')

    report_path = os.path.join(output_dir, filename)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(xml_parts))

    return report_path
