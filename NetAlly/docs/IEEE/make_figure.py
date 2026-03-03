import matplotlib.pyplot as plt
import numpy as np
import os
import seaborn as sns

# IEEE TNSM Figure Guidelines
# 2-column format. Font >= 10pt.
# Okabe-Ito colorblind friendly palette
# Colors:
# Orange: #E69F00, Skyblue: #56B4E9, Green: #009E73, Yellow: #F0E442
# Blue: #0072B2, Red: #D55E00, Pink: #CC79A7, Black: #000000

COLORS = ['#E69F00', '#56B4E9', '#009E73', '#F0E442', '#0072B2', '#D55E00', '#CC79A7', '#000000']
HATCHES = ['///', '\\\\', 'xx', 'oo', '++', '--']

plt.rcParams.update({
    'font.size': 11,
    'axes.labelsize': 12,
    'axes.titlesize': 12,
    'xtick.labelsize': 11,
    'ytick.labelsize': 11,
    'legend.fontsize': 10,
    'pdf.fonttype': 42, # TrueType
    'ps.fonttype': 42
})

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))

def save_fig(fig, filename):
    filepath = os.path.join(OUTPUT_DIR, filename)
    fig.tight_layout()
    fig.savefig(filepath, format='pdf', bbox_inches='tight', dpi=300)
    print(f"Saved {filepath}")

def generate_fig4():
    """
    Fig. 4: 레벨별 TA-Acc — L4 절벽
    Grouped Bar Chart, 6 models x 5 levels
    """
    levels = ['L1', 'L2', 'L3', 'L4', 'L5']
    models = ['Model A', 'Model B', 'Model C', 'Model D', 'Model E', 'Model F']
    
    # Dummy data
    data = {
        'Model A': [0.95, 0.90, 0.85, 0.40, 0.35],
        'Model B': [0.92, 0.88, 0.80, 0.38, 0.32],
        'Model C': [0.98, 0.94, 0.88, 0.45, 0.40],
        'Model D': [0.85, 0.80, 0.70, 0.25, 0.20],
        'Model E': [0.88, 0.82, 0.75, 0.30, 0.25],
        'Model F': [0.99, 0.96, 0.90, 0.50, 0.45],
    }
    
    x = np.arange(len(levels))
    width = 0.12
    multiplier = 0
    
    fig, ax = plt.subplots(figsize=(8, 5))
    
    for i, model in enumerate(models):
        offset = width * multiplier
        rects = ax.bar(x + offset, data[model], width, label=model, 
                       color=COLORS[i % len(COLORS)], edgecolor='black', hatch=HATCHES[i % len(HATCHES)])
        multiplier += 1

    ax.set_ylabel('TA-Acc (Topology-Aware Accuracy)')
    ax.set_title('Figure 4: TA-Acc by Cognitive Level')
    ax.set_xticks(x + width * 2.5)
    ax.set_xticklabels(levels)
    ax.set_ylim(0, 1.1)
    ax.legend(loc='upper right', ncol=2)
    
    # Simulation Barrier (L3-L4)
    barrier_x = 2 + width*6
    ax.axvline(x=barrier_x, color='red', linestyle='--', linewidth=2)
    ax.text(barrier_x + 0.1, 0.6, 'Simulation\nBarrier', color='red', fontsize=12, fontweight='bold')
    
    save_fig(fig, 'fig4_ta_acc_levels.pdf')

def generate_fig5():
    """
    Fig. 5: 3-Way 비교 — 구조 vs 도구
    3 groups (Single / Pure MAS / NetAlly) x 5 levels
    """
    levels = ['L1', 'L2', 'L3', 'L4', 'L5']
    groups = ['Single LLM', 'Pure MAS', 'NetAlly']
    
    # Dummy data
    data = {
        'Single LLM': [0.85, 0.80, 0.70, 0.30, 0.25],
        'Pure MAS': [0.90, 0.88, 0.82, 0.35, 0.30],
        'NetAlly': [0.95, 0.92, 0.88, 0.80, 0.75],
    }
    
    x = np.arange(len(levels))
    width = 0.25
    multiplier = 0
    
    fig, ax = plt.subplots(figsize=(8, 5))
    
    for i, group in enumerate(groups):
        offset = width * multiplier
        rects = ax.bar(x + offset, data[group], width, label=group, 
                       color=COLORS[i * 2], edgecolor='black', hatch=HATCHES[i])
        multiplier += 1

    ax.set_ylabel('TA-Acc')
    ax.set_title('Figure 5: 3-Way Comparison (Single vs MAS vs NetAlly)')
    ax.set_xticks(x + width)
    ax.set_xticklabels(levels)
    ax.set_ylim(0, 1.1)
    ax.legend(loc='upper right')
    
    # Arrow for Δ(Architecture) and Δ(Tool)
    # Just an example annotation
    ax.annotate(r'$\Delta$ (Architecture)', xy=(3, 0.35), xytext=(3, 0.55),
                arrowprops=dict(facecolor='black', shrink=0.05, width=1, headwidth=6))
    ax.annotate(r'$\Delta$ (Tool)', xy=(3 + width*2, 0.80), xytext=(3 + width*2, 0.55),
                arrowprops=dict(facecolor='black', shrink=0.05, width=1, headwidth=6))
    
    save_fig(fig, 'fig5_3way_comparison.pdf')

def generate_fig6():
    """
    Fig. 6: Scalability — 노드 수 vs TA-Acc
    Line chart for Node counts vs TA-Acc, 5 lines for L1~L5
    """
    nodes = [10, 20, 30, 40]
    levels = ['L1', 'L2', 'L3', 'L4', 'L5']
    
    # Dummy data
    data = {
        'L1': [0.98, 0.97, 0.96, 0.95],
        'L2': [0.95, 0.92, 0.88, 0.85],
        'L3': [0.90, 0.85, 0.78, 0.70],
        'L4': [0.45, 0.35, 0.25, 0.15],
        'L5': [0.40, 0.30, 0.20, 0.10],
    }
    
    fig, ax = plt.subplots(figsize=(7, 5))
    
    markers = ['o', 's', '^', 'D', 'v']
    
    for i, level in enumerate(levels):
        ax.plot(nodes, data[level], marker=markers[i], markersize=8, linewidth=2,
                label=level, color=COLORS[i])

    ax.set_xlabel('Number of Nodes')
    ax.set_ylabel('TA-Acc')
    ax.set_title('Figure 6: Scalability (Node count vs TA-Acc)')
    ax.set_xticks(nodes)
    ax.set_ylim(0, 1.1)
    ax.grid(True, linestyle='--', alpha=0.7)
    ax.legend(loc='lower left')
    
    save_fig(fig, 'fig6_scalability.pdf')

if __name__ == '__main__':
    generate_fig4()
    generate_fig5()
    generate_fig6()
    print("All figures successfully generated.")
