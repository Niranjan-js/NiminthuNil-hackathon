import sys

sys.stdout.reconfigure(encoding='utf-8')

with open('backend/main.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

print("Graph endpoints in main.py:")
for i, line in enumerate(lines):
    if '/api/v1/graph/' in line or 'class GraphNodeModel' in line or 'class GraphEdgeModel' in line:
        print(f"Line {i+1}: {line.strip()}")
        # print 15 lines of context
        for j in range(1, 15):
            if i + j < len(lines):
                print(f"  +{j}: {lines[i+j].rstrip()}")
        print("-" * 40)
