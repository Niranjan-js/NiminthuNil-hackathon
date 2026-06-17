import json
from sqlalchemy.orm import Session
from typing import List, Dict, Any, Optional
from main import GraphNodeModel, GraphEdgeModel

class KnowledgeGraphEngine:
    """
    Knowledge Graph Ontology Engine (Tier 7 & 30).
    Manages semantic nodes and edges representing the relationships
    between Assets, Users, Vulnerabilities, Threats, IOCs, Incidents, and Campaigns.
    """

    @staticmethod
    def add_or_update_node(db: Session, entity_type: str, entity_id: str, name: str, risk_weight: int = 50, properties: Dict[str, Any] = None) -> GraphNodeModel:
        """Adds a new node or updates an existing one in the knowledge graph."""
        node = db.query(GraphNodeModel).filter(
            GraphNodeModel.entity_type == entity_type,
            GraphNodeModel.entity_id == entity_id
        ).first()

        if not node:
            node = GraphNodeModel(
                entity_type=entity_type,
                entity_id=entity_id,
                name=name,
                risk_weight=risk_weight,
                properties=json.dumps(properties or {})
            )
            db.add(node)
        else:
            node.name = name
            node.risk_weight = risk_weight
            props = json.loads(node.properties or "{}")
            if properties:
                props.update(properties)
            node.properties = json.dumps(props)
        
        db.commit()
        db.refresh(node)
        return node

    @staticmethod
    def add_relationship(db: Session, source_type: str, source_id: str, target_type: str, target_id: str, relationship: str, weight: float = 1.0, properties: Dict[str, Any] = None) -> GraphEdgeModel:
        """Adds a relationship (directed edge) between two nodes in the graph."""
        # Check if edge already exists
        edge = db.query(GraphEdgeModel).filter(
            GraphEdgeModel.source_type == source_type,
            GraphEdgeModel.source_id == source_id,
            GraphEdgeModel.target_type == target_type,
            GraphEdgeModel.target_id == target_id,
            GraphEdgeModel.relationship == relationship
        ).first()

        if not edge:
            edge = GraphEdgeModel(
                source_type=source_type,
                source_id=source_id,
                target_type=target_type,
                target_id=target_id,
                relationship=relationship,
                weight=weight,
                properties=json.dumps(properties or {})
            )
            db.add(edge)
        else:
            edge.weight = weight
            props = json.loads(edge.properties or "{}")
            if properties:
                props.update(properties)
            edge.properties = json.dumps(props)

        db.commit()
        db.refresh(edge)
        return edge

    @staticmethod
    def search_graph(db: Session, query: Optional[str] = None, entity_type: Optional[str] = None) -> Dict[str, Any]:
        """Queries the graph nodes and edges with optional filters."""
        nodes_query = db.query(GraphNodeModel)
        if entity_type:
            nodes_query = nodes_query.filter(GraphNodeModel.entity_type == entity_type)
        if query:
            nodes_query = nodes_query.filter(GraphNodeModel.name.like(f"%{query}%") | GraphNodeModel.entity_id.like(f"%{query}%"))
        
        nodes = nodes_query.all()
        edges = db.query(GraphEdgeModel).all()

        # Build list of active node IDs to filter orphan edges
        node_ids = {f"{n.entity_type}:{n.entity_id}" for n in nodes}
        
        filtered_edges = []
        for e in edges:
            src_key = f"{e.source_type}:{e.source_id}"
            tgt_key = f"{e.target_type}:{e.target_id}"
            # Keep edge if both source and target exist in filtered nodes (or if no filter was applied)
            if not query and not entity_type:
                filtered_edges.append(e)
            elif src_key in node_ids or tgt_key in node_ids:
                filtered_edges.append(e)

        return {
            "nodes": [
                {
                    "id": n.id,
                    "entity_type": n.entity_type,
                    "entity_id": n.entity_id,
                    "name": n.name,
                    "risk_weight": n.risk_weight,
                    "properties": json.loads(n.properties or "{}")
                } for n in nodes
            ],
            "edges": [
                {
                    "id": e.id,
                    "source_type": e.source_type,
                    "source_id": e.source_id,
                    "target_type": e.target_type,
                    "target_id": e.target_id,
                    "relationship": e.relationship,
                    "weight": e.weight,
                    "properties": json.loads(e.properties or "{}")
                } for e in filtered_edges
            ]
        }
