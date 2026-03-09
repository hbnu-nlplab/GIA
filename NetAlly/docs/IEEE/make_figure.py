import json
import os

import matplotlib.pyplot as plt
import numpy as np

# Publication-oriented defaults for IEEE/TNSM single-column figures.
OKABE_ITO = [
    '#E69F00', '#56B4E9', '#009E73', '#F0E442',
    '#0072B2', '#D55E00', '#CC79A7', '#000000',
]
HATCHES = ['///', '\\\\', 'xx', 'oo', '++', '--']
MARKERS = ['o', 's', '^', 'D', 'v']

plt.rcParams.update({
    'font.family': 'sans-serif',
    'font.sans-serif': ['Arial', 'Helvetica', 'DejaVu Sans'],
    'font.size': 8,
    'axes.labelsize': 9,
    'axes.titlesize': 9,
    'xtick.labelsize': 8,
    'ytick.labelsize': 8,
    'legend.fontsize': 7,
    'axes.linewidth': 0.8,
    'xtick.major.width': 0.8,
    'ytick.major.width': 0.8,
    'pdf.fonttype': 42,
    'ps.fonttype': 42,
})

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))

DEFAULT_FIG4_DATA = {
    'GPT-4o-mini': [0.95, 0.90, 0.85, 0.40, 0.35],
    'GPT-OSS-20B': [0.92, 0.88, 0.80, 0.38, 0.32],
    'Qwen3-Coder': [0.98, 0.94, 0.88, 0.45, 0.40],
    'Gemma-3-27B': [0.85, 0.80, 0.70, 0.25, 0.20],
    'GLM-4.7-Flash': [0.88, 0.82, 0.75, 0.30, 0.25],
    'Qwen3.5-27B': [0.99, 0.96, 0.90, 0.50, 0.45],
}

DEFAULT_FIG5_DATA = {
    'Single LLM': [0.85, 0.80, 0.70, 0.30, 0.25],
    'Pure MAS': [0.90, 0.88, 0.82, 0.35, 0.30],
    'NetAlly': [0.95, 0.92, 0.88, 0.80, 0.75],
}

DEFAULT_FIG6_DATA = {
    'L1': [0.98, 0.97, 0.96, 0.95],
    'L2': [0.95, 0.92, 0.88, 0.85],
    'L3': [0.90, 0.85, 0.78, 0.70],
    'L4': [0.45, 0.35, 0.25, 0.15],
    'L5': [0.40, 0.30, 0.20, 0.10],
}


DEFAULT_DATA_PATH = os.path.join(OUTPUT_DIR, 'figure_data.json')


def load_figure_data():
    """Load figure values from JSON if available, else use defaults."""
    figure_data = {
        'fig4': DEFAULT_FIG4_DATA,
        'fig5': DEFAULT_FIG5_DATA,
        'fig6': DEFAULT_FIG6_DATA,
    }

    if not os.path.exists(DEFAULT_DATA_PATH):
        return figure_data

    with open(DEFAULT_DATA_PATH, 'r', encoding='utf-8') as f:
        loaded = json.load(f)

    for key in figure_data:
        if key in loaded:
            figure_data[key] = loaded[key]
    return figure_data


def style_axes(ax):
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.tick_params(direction='out', length=3)
    ax.grid(axis='y', linestyle='--', linewidth=0.5, alpha=0.35)


def save_fig(fig, filename):
    filepath = os.path.join(OUTPUT_DIR, filename)
    fig.tight_layout(pad=0.4)
    fig.savefig(filepath, format='pdf', bbox_inches='tight')
    print(f"Saved {filepath}")


def generate_fig4():
    """Fig. 4: Level-wise TA-Acc with simulation barrier annotation."""
    figure_data = load_figure_data()
    levels = ['L1', 'L2', 'L3', 'L4', 'L5']
    models = list(figure_data['fig4'].keys())
    x = np.arange(len(levels))
    width = 0.12

    fig, ax = plt.subplots(figsize=(3.5, 2.8))

    for i, model in enumerate(models):
        ax.bar(
            x + (i - 2.5) * width,
            figure_data['fig4'][model],
            width,
            label=model,
            color=OKABE_ITO[i],
            edgecolor='black',
            linewidth=0.6,
            hatch=HATCHES[i % len(HATCHES)],
        )

    style_axes(ax)
    ax.set_ylabel('TA-Acc')
    ax.set_xticks(x)
    ax.set_xticklabels(levels)
    ax.set_ylim(0.0, 1.02)
    ax.legend(frameon=False, ncol=2, loc='upper right', handlelength=1.6, columnspacing=0.8)

    barrier_x = 2.5
    ax.axvline(barrier_x, color='#666666', linestyle='--', linewidth=1.0)
    ax.text(barrier_x + 0.08, 0.58, 'Simulation\nBarrier', color='#444444', fontsize=7, va='center')

    save_fig(fig, 'fig4_ta_acc_levels.pdf')


def generate_fig5():
    """Fig. 5: 3-way comparison for architecture vs tool contribution."""
    figure_data = load_figure_data()
    levels = ['L1', 'L2', 'L3', 'L4', 'L5']
    groups = list(figure_data['fig5'].keys())
    x = np.arange(len(levels))
    width = 0.22

    fig, ax = plt.subplots(figsize=(3.5, 2.8))

    group_colors = [OKABE_ITO[4], OKABE_ITO[0], OKABE_ITO[2]]
    for i, group in enumerate(groups):
        ax.bar(
            x + (i - 1) * width,
            figure_data['fig5'][group],
            width,
            label=group,
            color=group_colors[i],
            edgecolor='black',
            linewidth=0.6,
            hatch=HATCHES[i],
        )

    style_axes(ax)
    ax.set_ylabel('TA-Acc')
    ax.set_xticks(x)
    ax.set_xticklabels(levels)
    ax.set_ylim(0.0, 1.02)
    ax.legend(frameon=False, loc='upper left')

    l4_x = x[3]
    ax.annotate(
        r'$\Delta$(structure)',
        xy=(l4_x, figure_data['fig5']['Pure MAS'][3]),
        xytext=(l4_x - 0.55, 0.52),
        fontsize=7,
        arrowprops=dict(arrowstyle='->', lw=0.8, color='black'),
    )
    ax.annotate(
        r'$\Delta$(tool)',
        xy=(l4_x + width, figure_data['fig5']['NetAlly'][3]),
        xytext=(l4_x + 0.10, 0.67),
        fontsize=7,
        arrowprops=dict(arrowstyle='->', lw=0.8, color='black'),
    )

    save_fig(fig, 'fig5_3way_comparison.pdf')


def generate_fig6():
    """Fig. 6: Scalability across topology size."""
    figure_data = load_figure_data()
    nodes = [10, 20, 30, 40]
    levels = list(figure_data['fig6'].keys())

    fig, ax = plt.subplots(figsize=(3.5, 2.8))

    for i, level in enumerate(levels):
        ax.plot(
            nodes,
            figure_data['fig6'][level],
            marker=MARKERS[i],
            markersize=4.5,
            linewidth=1.5,
            label=level,
            color=OKABE_ITO[i],
        )

    style_axes(ax)
    ax.set_xlabel('Number of nodes')
    ax.set_ylabel('TA-Acc')
    ax.set_xticks(nodes)
    ax.set_ylim(0.0, 1.02)
    ax.legend(frameon=False, loc='lower left', ncol=2)

    save_fig(fig, 'fig6_scalability.pdf')


if __name__ == '__main__':
    generate_fig4()
    generate_fig5()
    generate_fig6()
    print('All figures successfully generated.')
