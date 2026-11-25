import { Card, EmptyState } from "../components/ui";
import { useI18n } from "../i18n";

export default function Stub({ title, phase }: { title: string; phase: string }) {
  const { t } = useI18n();
  return (
    <Card title={title}>
      <EmptyState text={`${t("wip")} (${phase})`} />
    </Card>
  );
}
