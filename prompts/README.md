# GPT 系列破甲提示词（gpt-5.6-instruct v42）

来源：[MDX-Tom/gpt-5.6-instruct](https://github.com/MDX-Tom/gpt-5.6-instruct)（MIT）

| 文件 | 说明 |
| --- | --- |
| `gpt-5.6-sol-unrestricted-v42.md` | 生产正文 |
| `gpt-5.6-sol-unrestricted-v42.zip` | 上游发布包（SHA256 与上游一致） |

运行时由 `internal/gptinstruct` 按**模型名**注入（仅 `gpt-*` / `chatgpt-*`），与 provider / OpenAI 协议无关。

配置见 `config.example.yaml` → `agent.gpt_instruct`。