"""Analysis pipeline orchestration."""

from __future__ import annotations

import asyncio
from typing import Callable, Awaitable

from .context import AnalysisContext, AnalysisError
from .config import AnalysisConfig
from .errors import RTOSAnalyzerError


class PipelineStage:
    def __init__(
        self,
        name: str,
        runner: Callable[[AnalysisContext], Awaitable[AnalysisContext]],
        is_critical: bool = False,
    ):
        self.name = name
        self._runner = runner
        self.is_critical = is_critical

    async def run(self, context: AnalysisContext) -> AnalysisContext:
        return await self._runner(context)


class AnalysisPipeline:
    def __init__(self, config: AnalysisConfig):
        self._stages: list[PipelineStage] = []
        self._config = config

    def add_stage(
        self,
        name: str,
        runner: Callable[[AnalysisContext], Awaitable[AnalysisContext]],
        is_critical: bool = False,
    ) -> "AnalysisPipeline":
        self._stages.append(PipelineStage(name, runner, is_critical))
        return self

    async def execute(self, context: AnalysisContext) -> AnalysisContext:
        for stage in self._stages:
            try:
                context = await stage.run(context)
            except RTOSAnalyzerError as e:
                context.errors.append(
                    AnalysisError(stage=stage.name, message=str(e), fatal=stage.is_critical)
                )
                if stage.is_critical:
                    raise
            except Exception as e:
                context.errors.append(
                    AnalysisError(stage=stage.name, message=f"Unexpected: {e}", fatal=False)
                )
        return context

    def run_sync(self, context: AnalysisContext) -> AnalysisContext:
        return asyncio.run(self.execute(context))
