from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
app = FastAPI(title="Sentinel Privacy Middleware")
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()
class AnonymizeRequest(BaseModel):
    text: str
class DeanonymizeRequest(BaseModel):
    ai_response: str
    mapping: Dict[str, str]
@app.post("/anonymize")
async def anonymize_text(request: AnonymizeRequest):
    results = analyzer.analyze(
        text=request.text, 
        entities=["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "LOCATION"], 
        language='en'
    )
    
    mapping = {}
    for res in results:
        original_val = request.text[res.start:res.end]
        placeholder = f"<{res.entity_type}>"
        mapping[placeholder] = original_val
    
    anonymized_result = anonymizer.anonymize(text=request.text, analyzer_results=results)
    return {
        "clean_text": anonymized_result.text,
        "mapping": mapping
    }

@app.post("/deanonymize")
async def deanonymize_text(request: DeanonymizeRequest):
    final_text = request.ai_response
    for placeholder, real_data in request.mapping.items():
        final_text = final_text.replace(placeholder, real_data)
    return {"real_human_text": final_text}