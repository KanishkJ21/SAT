import io,json,pandas as pd
def csv_bytes(d):return d.to_csv(index=False).encode()
def json_bytes(d):return json.dumps(d.to_dict("records"),indent=2,default=str).encode()
def xlsx_bytes(d):
 b=io.BytesIO()
 with pd.ExcelWriter(b,engine="openpyxl") as w:d.to_excel(w,index=False,sheet_name="Findings")
 return b.getvalue()
def pdf_bytes(d):
 try:
  from reportlab.lib.pagesizes import A4
  from reportlab.pdfgen import canvas
 except Exception:return None
 b=io.BytesIO();p=canvas.Canvas(b,pagesize=A4);w,h=A4;p.setFont("Helvetica-Bold",16);p.drawString(40,h-45,"SAT-SA Supervisory Analytics Report");p.setFont("Helvetica",8);y=h-70
 for _,r in d.head(45).iterrows():
  p.drawString(40,y,f"{r.finding_id} | {r.entity_code} | {r.severity} | {r.score:.0f} | {r.title}"[:120]);y-=14
  if y<35:p.showPage();p.setFont("Helvetica",8);y=h-45
 p.save();b.seek(0);return b.getvalue()
