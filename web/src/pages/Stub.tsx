import { Card, EmptyState } from "../components/ui";
import { useI18n } from "../i18n";

export default function Stub({ title, titleKey, phase }: { title?: string; titleKey?: string; phase: string }) {
  const { t } = useI18n();
  return (
    <Card title={titleKey ? t(titleKey) : title}>
      <EmptyState text={`${t("wip")} (${phase})`} />
    </Card>
  );
}
