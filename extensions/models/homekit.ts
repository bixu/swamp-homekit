import { z } from "npm:zod@4";
import bonjourModule from "npm:bonjour-service@1.3.0";
import { extractSensorReadings, pairSetup, pairVerify } from "./homekit_hap.ts";

// deno-lint-ignore no-explicit-any
const Bonjour = (bonjourModule as any).default || bonjourModule;

const HAP_SERVICE_TYPE = "hap";

const GlobalArgsSchema = z.object({
  discoveryTimeout: z.number().default(10).describe(
    "Seconds to wait for mDNS discovery (default: 10)",
  ),
});

const CategoryNames: Record<number, string> = {
  1: "Other",
  2: "Bridge",
  3: "Fan",
  4: "Garage Door Opener",
  5: "Lightbulb",
  6: "Door Lock",
  7: "Outlet",
  8: "Switch",
  9: "Thermostat",
  10: "Sensor",
  11: "Security System",
  12: "Door",
  13: "Window",
  14: "Window Covering",
  15: "Programmable Switch",
  16: "Range Extender",
  17: "IP Camera",
  18: "Video Doorbell",
  19: "Air Purifier",
  20: "Heater",
  21: "Air Conditioner",
  22: "Humidifier",
  23: "Dehumidifier",
  28: "Sprinkler",
  29: "Faucet",
  30: "Shower",
  32: "Television",
  33: "Remote Control",
  34: "Router",
};

const AccessorySchema = z.object({
  name: z.string(),
  address: z.string(),
  port: z.number(),
  id: z.string(),
  model: z.string(),
  category: z.string(),
  categoryId: z.number(),
  configNumber: z.number(),
  stateNumber: z.number(),
  protocolVersion: z.string(),
  paired: z.boolean(),
  discoveredAt: z.string(),
});

const DiscoverySchema = z.object({
  totalAccessories: z.number(),
  timeoutSeconds: z.number(),
  accessories: z.array(AccessorySchema),
  discoveredAt: z.string(),
});

const SummarySchema = z.object({
  method: z.string(),
  totalAccessories: z.number(),
  summary: z.string(),
  details: z.record(z.string(), z.union([z.string(), z.number()])),
  generatedAt: z.string(),
});

const PairingSchema = z.object({
  accessoryId: z.string(),
  accessoryLTPK: z.string(),
  clientLTSK: z.string().meta({ sensitive: true }),
  clientLTPK: z.string(),
  pairedAt: z.string(),
});

const SensorCharacteristicSchema = z.object({
  name: z.string(),
  type: z.string(),
  value: z.union([z.number(), z.string(), z.boolean()]),
  unit: z.string().optional(),
});

const SensorReadingSchema = z.object({
  accessoryName: z.string(),
  accessoryAddress: z.string(),
  serviceName: z.string(),
  serviceType: z.string(),
  characteristics: z.array(SensorCharacteristicSchema),
  readAt: z.string(),
});

const SensorSummarySchema = z.object({
  method: z.string(),
  totalReadings: z.number(),
  summary: z.string(),
  details: z.record(z.string(), z.union([z.string(), z.number()])),
  generatedAt: z.string(),
});

function discoverAccessories(
  timeout: number,
): Promise<Record<string, unknown>[]> {
  return new Promise((resolve) => {
    const bonjour = new Bonjour();
    const found: Record<string, unknown>[] = [];

    const browser = bonjour.find(
      { type: HAP_SERVICE_TYPE, protocol: "tcp" },
      // deno-lint-ignore no-explicit-any
      (service: any) => {
        found.push({
          name: service.name,
          host: service.host,
          port: service.port,
          addresses: service.addresses,
          txt: service.txt,
        });
      },
    );

    setTimeout(() => {
      browser.stop();
      bonjour.destroy();
      resolve(found);
    }, timeout * 1000);
  });
}

export const model = {
  type: "@bixu/homekit",
  version: "2026.03.14.3",
  globalArguments: GlobalArgsSchema,
  resources: {
    discovery: {
      description: "Discovered HomeKit accessories on the local network",
      schema: DiscoverySchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    accessory: {
      description: "Individual HomeKit accessory",
      schema: AccessorySchema,
      lifetime: "infinite" as const,
      garbageCollection: 50,
    },
    summary: {
      description: "Summary of a discovery or sensor operation",
      schema: SummarySchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    pairing: {
      description: "Stored pairing credentials for a HomeKit accessory",
      schema: PairingSchema,
      lifetime: "infinite" as const,
      garbageCollection: 5,
    },
    sensorReading: {
      description: "Sensor reading from a paired HomeKit accessory",
      schema: SensorReadingSchema,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
    sensorSummary: {
      description: "Summary of sensor readings",
      schema: SensorSummarySchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
  },
  methods: {
    discover: {
      description: "Discover HomeKit accessories on the local network via mDNS",
      arguments: z.object({
        timeout: z.number().optional().describe(
          "Override discovery timeout in seconds",
        ),
      }),
      execute: async (args, context) => {
        const g = context.globalArgs;
        const timeout = args.timeout ?? g.discoveryTimeout;

        context.logger.info("Starting HomeKit mDNS discovery ({timeout}s)", {
          timeout,
        });

        const raw = await discoverAccessories(timeout);

        // deno-lint-ignore no-explicit-any
        const accessories = raw.map((d: any) => {
          const txt = d.txt || {};
          const ci = Number(txt.ci || 0);
          return {
            name: String(d.name || "Unknown"),
            address: ((d.addresses as string[]) || []).find((a: string) =>
              a.includes(".")
            ) || String(d.host || ""),
            port: Number(d.port || 0),
            id: String(txt.id || ""),
            model: String(txt.md || "Unknown"),
            category: CategoryNames[ci] || `Unknown (${ci})`,
            categoryId: ci,
            configNumber: Number(txt["c#"] || 0),
            stateNumber: Number(txt["s#"] || 0),
            protocolVersion: String(txt.pv || ""),
            paired: txt.sf === "0" || txt.sf === 0,
            discoveredAt: new Date().toISOString(),
          };
        });

        const handles = [];

        for (const acc of accessories) {
          const handle = await context.writeResource(
            "accessory",
            acc.id.replace(/:/g, "-"),
            acc,
          );
          handles.push(handle);
        }

        const discoveryHandle = await context.writeResource(
          "discovery",
          "latest",
          {
            totalAccessories: accessories.length,
            timeoutSeconds: timeout,
            accessories,
            discoveredAt: new Date().toISOString(),
          },
        );

        const categoryCounts: Record<string, number> = {};
        for (const acc of accessories) {
          categoryCounts[acc.category] = (categoryCounts[acc.category] || 0) +
            1;
        }
        const categoryParts = Object.entries(categoryCounts)
          .map(([cat, n]) => `${cat}: ${n}`)
          .join(", ");
        const pairedCount = accessories.filter((a) => a.paired).length;

        const summaryHandle = await context.writeResource(
          "summary",
          "discover",
          {
            method: "discover",
            totalAccessories: accessories.length,
            summary:
              `${accessories.length} accessories found — ${categoryParts} | ${pairedCount} paired`,
            details: {
              ...categoryCounts,
              paired: pairedCount,
              unpaired: accessories.length - pairedCount,
            },
            generatedAt: new Date().toISOString(),
          },
        );

        return { dataHandles: [summaryHandle, discoveryHandle, ...handles] };
      },
    },

    pair: {
      description:
        "Pair with a HomeKit accessory using its setup code (from the accessory label or app)",
      arguments: z.object({
        accessoryName: z.string().describe(
          "Name of a discovered accessory to pair with",
        ),
        setupCode: z.string().describe(
          "8-digit setup code in XXX-XX-XXX format",
        ),
      }),
      execute: async (args, context) => {
        context.logger.info("Pairing with {name}", {
          name: args.accessoryName,
        });

        // Look up accessory from discovery data
        const discovery = await context.dataRepository.getContent(
          context.definition.id,
          "discovery",
          "latest",
        );

        if (!discovery) {
          throw new Error(
            "No discovery data. Run 'discover' first to find accessories.",
          );
        }

        // deno-lint-ignore no-explicit-any
        const acc = (discovery as any).accessories?.find(
          // deno-lint-ignore no-explicit-any
          (a: any) =>
            a.name.toLowerCase().includes(args.accessoryName.toLowerCase()),
        );
        if (!acc) {
          throw new Error(
            `Accessory "${args.accessoryName}" not found in discovery data`,
          );
        }

        context.logger.info("Connecting to {address}:{port}", {
          address: acc.address,
          port: acc.port,
        });

        const pairing = await pairSetup(acc.address, acc.port, args.setupCode);

        const handle = await context.writeResource(
          "pairing",
          acc.id.replace(/:/g, "-"),
          {
            ...pairing,
            pairedAt: new Date().toISOString(),
          },
        );

        return { dataHandles: [handle] };
      },
    },

    readSensors: {
      description:
        "Read sensor data (temperature, humidity, etc.) from a paired accessory",
      arguments: z.object({
        accessoryName: z.string().describe(
          "Name of a discovered accessory to read sensors from",
        ),
      }),
      execute: async (args, context) => {
        // Look up accessory
        const discovery = await context.dataRepository.getContent(
          context.definition.id,
          "discovery",
          "latest",
        );
        if (!discovery) {
          throw new Error("No discovery data. Run 'discover' first.");
        }

        // deno-lint-ignore no-explicit-any
        const acc = (discovery as any).accessories?.find(
          // deno-lint-ignore no-explicit-any
          (a: any) =>
            a.name.toLowerCase().includes(args.accessoryName.toLowerCase()),
        );
        if (!acc) {
          throw new Error(
            `Accessory "${args.accessoryName}" not found in discovery data`,
          );
        }

        // Look up pairing
        const pairingId = acc.id.replace(/:/g, "-");
        const pairing = await context.dataRepository.getContent(
          context.definition.id,
          "pairing",
          pairingId,
        );
        if (!pairing) {
          throw new Error(
            `No pairing for "${acc.name}". Run 'pair' first with the setup code.`,
          );
        }

        context.logger.info("Connecting to {name} at {address}:{port}", {
          name: acc.name,
          address: acc.address,
          port: acc.port,
        });

        // deno-lint-ignore no-explicit-any
        const session = await pairVerify(acc.address, acc.port, pairing as any);

        try {
          // Read accessory database
          const dbResp = await session.request("GET", "/accessories");
          const db = dbResp.body;

          // Extract sensor readings
          const readings = extractSensorReadings(db);

          const handles = [];
          const summaryLines: string[] = [];

          for (const reading of readings) {
            const instanceName = `${pairingId}-${
              reading.serviceName.replace(/[^a-zA-Z0-9]/g, "-").toLowerCase()
            }`;
            const handle = await context.writeResource(
              "sensorReading",
              instanceName,
              {
                accessoryName: acc.name,
                accessoryAddress: acc.address,
                serviceName: reading.serviceName,
                serviceType: reading.serviceType,
                characteristics: reading.characteristics,
                readAt: new Date().toISOString(),
              },
            );
            handles.push(handle);

            const values = reading.characteristics
              .map((c) => {
                const unit = c.unit === "celsius"
                  ? "°C"
                  : c.unit === "percentage"
                  ? "%"
                  : c.unit || "";
                return `${c.name}: ${c.value}${unit}`;
              })
              .join(", ");
            summaryLines.push(`${reading.serviceName}: ${values}`);
          }

          const summaryHandle = await context.writeResource(
            "sensorSummary",
            "latest",
            {
              method: "readSensors",
              totalReadings: readings.length,
              summary: summaryLines.join(" | ") || "No sensor readings found",
              details: Object.fromEntries(
                readings.flatMap((r) =>
                  r.characteristics.map((c) => [
                    `${r.serviceName}.${c.name}`,
                    c.value,
                  ])
                ),
              ),
              generatedAt: new Date().toISOString(),
            },
          );

          return { dataHandles: [summaryHandle, ...handles] };
        } finally {
          session.close();
        }
      },
    },
  },
};
